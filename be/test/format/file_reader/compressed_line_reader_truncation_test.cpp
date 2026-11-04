// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

// A compressed file that ends inside a compressed stream must fail the read. The line reader used
// to forget an unfinished stream between read_line() calls, so a file cut after complete lines (a
// gzip prefix ended by Z_SYNC_FLUSH, or one without its trailer) was loaded as its prefix.

#include <bzlib.h>
#include <gtest/gtest.h>
#include <lz4/lz4frame.h>
#include <zlib.h>
#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "format/file_reader/new_plain_text_line_reader.h"
#include "io/fs/file_reader.h"
#include "util/decompressor.h"

namespace doris {

namespace {

class InMemoryFileReader : public io::FileReader {
public:
    explicit InMemoryFileReader(std::string content) : _content(std::move(content)) {}
    Status close() override {
        _closed = true;
        return Status::OK();
    }
    const io::Path& path() const override { return _path; }
    size_t size() const override { return _content.size(); }
    bool closed() const override { return _closed; }
    int64_t mtime() const override { return 0; }

protected:
    Status read_at_impl(size_t offset, Slice result, size_t* bytes_read,
                        const io::IOContext*) override {
        *bytes_read = std::min(result.size, _content.size() - std::min(offset, _content.size()));
        if (*bytes_read > 0) {
            std::memcpy(result.mutable_data(), _content.data() + offset, *bytes_read);
        }
        return Status::OK();
    }

private:
    io::Path _path {"compressed-line-reader-test"};
    std::string _content;
    bool _closed = false;
};

struct ReadResult {
    Status status;
    std::vector<std::string> lines;
};

ReadResult read_lines(CompressType type, std::string content) {
    ReadResult result;
    std::unique_ptr<Decompressor> decompressor;
    result.status = Decompressor::create_decompressor(type, &decompressor);
    if (!result.status.ok()) {
        return result;
    }
    RuntimeProfile profile("compressed_line_reader");
    const size_t size = content.size();
    NewPlainTextLineReader reader(
            &profile, std::make_shared<InMemoryFileReader>(std::move(content)), decompressor.get(),
            std::make_shared<PlainTextLineReaderCtx>("\n", 1, false), size, 0);
    while (true) {
        const uint8_t* line = nullptr;
        size_t length = 0;
        bool eof = false;
        result.status = reader.read_line(&line, &length, &eof, nullptr);
        if (!result.status.ok() || eof) {
            return result;
        }
        result.lines.emplace_back(reinterpret_cast<const char*>(line), length);
    }
}

// Lines of random text, about 3.5 MB in all, so that the compressed file takes more than one read
// (2 MiB) and the decompressed one more than one output buffer.
std::vector<std::string> make_lines(uint32_t seed) {
    static const std::vector<std::string> specials = {"中文",
                                                      "😀👩🏽‍💻",
                                                      "\t",
                                                      "a\"b'c",
                                                      "\\",
                                                      "\xe2\x80\x8b",
                                                      "\xef\xbb\xbf",
                                                      ",|;",
                                                      "::ffff:1.2.3.4",
                                                      "2001:db8::1",
                                                      "\x01\x1f\x7f",
                                                      ""};
    std::mt19937 rng(seed);
    std::vector<std::string> lines;
    for (int i = 0; i < 1800; ++i) {
        std::string line = std::to_string(i) + ",";
        const auto length = std::uniform_int_distribution<int>(0, 3800)(rng);
        for (int j = 0; j < length; ++j) {
            line.push_back(static_cast<char>(std::uniform_int_distribution<int>(0x21, 0x7e)(rng)));
        }
        line += specials[rng() % specials.size()];
        lines.push_back(std::move(line));
    }
    return lines;
}

std::string join(const std::vector<std::string>& lines, size_t begin, size_t end) {
    std::string text;
    for (size_t i = begin; i < end; ++i) {
        text += lines[i];
        text += '\n';
    }
    return text;
}

// Compresses lines [0, flush_at) and flushes, then the rest; *flushed is the output up to the
// flush: complete lines that end inside the stream.
std::string zlib_compress(const std::vector<std::string>& lines, size_t flush_at, int window_bits,
                          std::string* flushed) {
    z_stream stream {};
    EXPECT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window_bits, 8,
                           Z_DEFAULT_STRATEGY),
              Z_OK);
    std::string out;
    auto run = [&](const std::string& in, int flush) {
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
        stream.avail_in = static_cast<uInt>(in.size());
        int ret = Z_OK;
        do {
            char buffer[65536];
            stream.next_out = reinterpret_cast<Bytef*>(buffer);
            stream.avail_out = sizeof(buffer);
            ret = deflate(&stream, flush);
            EXPECT_NE(ret, Z_STREAM_ERROR);
            out.append(buffer, sizeof(buffer) - stream.avail_out);
        } while (stream.avail_out == 0 || (flush == Z_FINISH && ret != Z_STREAM_END));
    };
    run(join(lines, 0, flush_at), Z_SYNC_FLUSH);
    *flushed = out;
    run(join(lines, flush_at, lines.size()), Z_FINISH);
    deflateEnd(&stream);
    return out;
}

std::string zstd_compress(const std::vector<std::string>& lines, size_t flush_at,
                          std::string* flushed) {
    ZSTD_CCtx* cctx = ZSTD_createCCtx();
    std::string out;
    auto run = [&](const std::string& in, ZSTD_EndDirective mode) {
        ZSTD_inBuffer input {in.data(), in.size(), 0};
        size_t remaining = 0;
        do {
            std::string buffer(ZSTD_CStreamOutSize(), '\0');
            ZSTD_outBuffer output {buffer.data(), buffer.size(), 0};
            remaining = ZSTD_compressStream2(cctx, &output, &input, mode);
            EXPECT_FALSE(ZSTD_isError(remaining));
            out.append(buffer.data(), output.pos);
        } while (remaining != 0 || input.pos < input.size);
    };
    run(join(lines, 0, flush_at), ZSTD_e_flush);
    *flushed = out;
    run(join(lines, flush_at, lines.size()), ZSTD_e_end);
    ZSTD_freeCCtx(cctx);
    return out;
}

std::string lz4_frame_compress(const std::vector<std::string>& lines, size_t flush_at,
                               std::string* flushed) {
    LZ4F_cctx* cctx = nullptr;
    EXPECT_FALSE(LZ4F_isError(LZ4F_createCompressionContext(&cctx, LZ4F_VERSION)));
    std::string out;
    std::string buffer(LZ4F_compressBound(4 << 20, nullptr) + 64, '\0');
    auto append = [&](size_t ret) {
        EXPECT_FALSE(LZ4F_isError(ret)) << LZ4F_getErrorName(ret);
        out.append(buffer.data(), ret);
    };
    append(LZ4F_compressBegin(cctx, buffer.data(), buffer.size(), nullptr));
    auto update = [&](const std::string& in) {
        for (size_t pos = 0; pos < in.size(); pos += 1 << 20) {
            const size_t length = std::min<size_t>(1 << 20, in.size() - pos);
            append(LZ4F_compressUpdate(cctx, buffer.data(), buffer.size(), in.data() + pos, length,
                                       nullptr));
        }
    };
    update(join(lines, 0, flush_at));
    append(LZ4F_flush(cctx, buffer.data(), buffer.size(), nullptr));
    *flushed = out;
    update(join(lines, flush_at, lines.size()));
    append(LZ4F_compressEnd(cctx, buffer.data(), buffer.size(), nullptr));
    LZ4F_freeCompressionContext(cctx);
    return out;
}

std::string bzip2_compress(const std::string& in) {
    std::string out(in.size() + in.size() / 100 + 600, '\0');
    auto length = static_cast<unsigned int>(out.size());
    EXPECT_EQ(BZ2_bzBuffToBuffCompress(out.data(), &length, const_cast<char*>(in.data()),
                                       static_cast<unsigned int>(in.size()), 9, 0, 0),
              BZ_OK);
    out.resize(length);
    return out;
}

void expect_complete(CompressType type, const std::string& compressed,
                     const std::vector<std::string>& lines) {
    auto result = read_lines(type, compressed);
    ASSERT_TRUE(result.status.ok()) << result.status;
    EXPECT_EQ(result.lines, lines);
}

// A truncated file fails, and every line returned before the failure is intact.
void expect_truncated(CompressType type, const std::string& compressed, size_t length,
                      const std::vector<std::string>& lines) {
    SCOPED_TRACE(::testing::Message() << "kept " << length << " of " << compressed.size());
    auto result = read_lines(type, compressed.substr(0, length));
    EXPECT_FALSE(result.status.ok()) << "loaded " << result.lines.size() << " lines";
    ASSERT_LE(result.lines.size(), lines.size());
    for (size_t i = 0; i < result.lines.size(); ++i) {
        ASSERT_EQ(result.lines[i], lines[i]) << i;
    }
}

} // namespace

TEST(CompressedLineReaderTruncationTest, Gzip) {
    const auto lines = make_lines(20261104);
    for (size_t flush_at : {size_t(17), size_t(900), lines.size() - 1}) {
        SCOPED_TRACE(::testing::Message() << "flush after line " << flush_at);
        std::string flushed;
        const auto gzip = zlib_compress(lines, flush_at, 15 + 16, &flushed);
        expect_complete(CompressType::GZIP, gzip, lines);
        // the prefix ends with complete lines, but not the gzip stream
        expect_truncated(CompressType::GZIP, flushed, flushed.size(), lines);
        expect_truncated(CompressType::GZIP, gzip, gzip.size() - 4, lines); // no ISIZE
        expect_truncated(CompressType::GZIP, gzip, gzip.size() - 8, lines); // no trailer
        expect_truncated(CompressType::GZIP, gzip, gzip.size() - 9, lines);
        expect_truncated(CompressType::GZIP, gzip, gzip.size() / 2, lines);
    }
}

TEST(CompressedLineReaderTruncationTest, ConcatenatedGzipMembersAreComplete) {
    const auto lines = make_lines(7);
    std::string unused;
    const std::vector<std::string> first(lines.begin(), lines.begin() + 1000);
    const std::vector<std::string> second(lines.begin() + 1000, lines.end());
    const auto gzip = zlib_compress(first, 3, 15 + 16, &unused) +
                      zlib_compress(second, 500, 15 + 16, &unused);
    expect_complete(CompressType::GZIP, gzip, lines);
    // cut inside the second member
    expect_truncated(CompressType::GZIP, gzip, gzip.size() - 8, lines);
}

TEST(CompressedLineReaderTruncationTest, Deflate) {
    const auto lines = make_lines(11);
    std::string flushed;
    const auto deflate = zlib_compress(lines, 61, 15, &flushed);
    expect_complete(CompressType::DEFLATE, deflate, lines);
    expect_truncated(CompressType::DEFLATE, flushed, flushed.size(), lines);
    expect_truncated(CompressType::DEFLATE, deflate, deflate.size() - 4, lines); // no Adler-32
}

TEST(CompressedLineReaderTruncationTest, Bzip2) {
    const auto lines = make_lines(13);
    const auto bzip2 = bzip2_compress(join(lines, 0, lines.size()));
    expect_complete(CompressType::BZIP2, bzip2, lines);
    expect_complete(
            CompressType::BZIP2,
            bzip2_compress(join(lines, 0, 5)) + bzip2_compress(join(lines, 5, lines.size())),
            lines);
    for (size_t length : {bzip2.size() - 1, bzip2.size() - 10, bzip2.size() * 3 / 4}) {
        expect_truncated(CompressType::BZIP2, bzip2, length, lines);
    }
}

TEST(CompressedLineReaderTruncationTest, Zstd) {
    const auto lines = make_lines(17);
    std::string flushed;
    const auto zstd = zstd_compress(lines, 1200, &flushed);
    expect_complete(CompressType::ZSTD, zstd, lines);
    std::string unused;
    expect_complete(
            CompressType::ZSTD,
            zstd_compress(std::vector<std::string>(lines.begin(), lines.begin() + 2), 1, &unused) +
                    zstd_compress(std::vector<std::string>(lines.begin() + 2, lines.end()), 9,
                                  &unused),
            lines);
    expect_truncated(CompressType::ZSTD, flushed, flushed.size(), lines);
    expect_truncated(CompressType::ZSTD, zstd, zstd.size() - 1, lines);
    expect_truncated(CompressType::ZSTD, zstd, zstd.size() / 2, lines);
}

TEST(CompressedLineReaderTruncationTest, Lz4Frame) {
    const auto lines = make_lines(19);
    std::string flushed;
    const auto lz4 = lz4_frame_compress(lines, 333, &flushed);
    expect_complete(CompressType::LZ4FRAME, lz4, lines);
    expect_truncated(CompressType::LZ4FRAME, flushed, flushed.size(), lines);
    expect_truncated(CompressType::LZ4FRAME, lz4, lz4.size() - 4, lines); // no end mark
    expect_truncated(CompressType::LZ4FRAME, lz4, lz4.size() / 2, lines);
}

// Files written by gzip, bzip2, lz4 and lzop are still read in full, and an LZOP file cut inside
// its header or a block fails. A file cut at a block boundary cannot be told from a complete one,
// as for the Hadoop block codecs.
TEST(CompressedLineReaderTruncationTest, FilesOfTheCompressionTools) {
    const std::string dir =
            std::string(getenv("ROOT")) + "/be/test/exec/test_data/plain_text_line_reader/";
    auto read_file = [](const std::string& path) {
        std::ifstream stream(path, std::ios::binary);
        EXPECT_TRUE(stream.good()) << path;
        std::stringstream buffer;
        buffer << stream.rdbuf();
        return buffer.str();
    };
    auto split = [](const std::string& text) {
        std::vector<std::string> lines;
        size_t begin = 0;
        while (begin < text.size()) {
            size_t end = text.find('\n', begin);
            if (end == std::string::npos) {
                end = text.size();
            }
            lines.push_back(text.substr(begin, end - begin));
            begin = end + 1;
        }
        return lines;
    };
    const std::vector<std::tuple<std::string, std::string, CompressType>> files = {
            {"test_file.csv.gz", "test_file.csv", CompressType::GZIP},
            {"limit.csv.gz", "limit.csv", CompressType::GZIP},
            {"no_newline.csv.gz", "no_newline.csv", CompressType::GZIP},
            {"test_file.csv.bz2", "test_file.csv", CompressType::BZIP2},
            {"limit.csv.bz2", "limit.csv", CompressType::BZIP2},
            {"test_file.csv.lz4", "test_file.csv", CompressType::LZ4FRAME},
            {"limit.csv.lz4", "limit.csv", CompressType::LZ4FRAME},
            {"test_file.csv.lzo", "test_file.csv", CompressType::LZOP},
            {"limit.csv.lzo", "limit.csv", CompressType::LZOP},
            {"larger.txt.lzo", "larger.txt", CompressType::LZOP}};
    for (const auto& [compressed_name, plain_name, type] : files) {
        SCOPED_TRACE(compressed_name);
        const auto lines = split(read_file(dir + plain_name));
        const auto compressed = read_file(dir + compressed_name);
        expect_complete(type, compressed, lines);
        expect_truncated(type, compressed, compressed.size() / 2, lines);
        if (type != CompressType::LZOP) {
            expect_truncated(type, compressed, compressed.size() - 1, lines);
        } else {
            // the last 4 bytes are the end marker; 5 more reach into the last block
            expect_truncated(type, compressed, compressed.size() - 5, lines);
        }
    }
}

} // namespace doris
