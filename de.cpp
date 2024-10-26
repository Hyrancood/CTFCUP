#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include <string>
#include <thread>
#include <fstream>
#include <algorithm>
#include <mutex>

const std::vector<int> SBOX = {
    1, 14, 27, 40, 53, 66, 79, 92, 105, 118, 131, 144, 157, 170, 183, 196, 209, 222, 235, 248, 5, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174, 187, 200, 213, 226, 239, 252, 9, 22, 35, 48, 61, 74, 87, 100, 113, 126, 139, 152, 165, 178, 191, 204, 217, 230, 243, 0, 13, 26, 39, 52, 65, 78, 91, 104, 117, 130, 143, 156, 169, 182, 195, 208, 221, 234, 247, 4, 17, 30, 43, 56, 69, 82, 95, 108, 121, 134, 147, 160, 173, 186, 199, 212, 225, 238, 251, 8, 21, 34, 47, 60, 73, 86, 99, 112, 125, 138, 151, 164, 177, 190, 203, 216, 229, 242, 255, 12, 25, 38, 51, 64, 77, 90, 103, 116, 129, 142, 155, 168, 181, 194, 207, 220, 233, 246, 3, 16, 29, 42, 55, 68, 81, 94, 107, 120, 133, 146, 159, 172, 185, 198, 211, 224, 237, 250, 7, 20, 33, 46, 59, 72, 85, 98, 111, 124, 137, 150, 163, 176, 189, 202, 215, 228, 241, 254, 11, 24, 37, 50, 63, 76, 89, 102, 115, 128, 141, 154, 167, 180, 193, 206, 219, 232, 245, 2, 15, 28, 41, 54, 67, 80, 93, 106, 119, 132, 145, 158, 171, 184, 197, 210, 223, 236, 249, 6, 19, 32, 45, 58, 71, 84, 97, 110, 123, 136, 149, 162, 175, 188, 201, 214, 227, 240, 253, 10, 23, 36, 49, 62, 75, 88, 101, 114, 127, 140, 153, 166, 179, 192, 205, 218, 231, 244
};
const int ROUNDS = 2;

std::vector<std::vector<uint8_t>> pts = {
    {0x47, 0x28, 0xc0, 0x57, 0xc9, 0x5e, 0xcc, 0xf6}, {0x6c, 0x16, 0x23, 0x42, 0xd8, 0xec, 0x43, 0x29},
    {0x13, 0x48, 0x71, 0x35, 0xb5, 0x74, 0x91, 0x19}, {0xed, 0xc9, 0x31, 0x4b, 0xcb, 0x16, 0xb7, 0xf5},
    {0x17, 0x61, 0x32, 0xf2, 0x7f, 0x2c, 0x90, 0x70}, {0x87, 0x2b, 0x24, 0x53, 0x48, 0xd8, 0x08, 0x56},
    {0x7d, 0x08, 0x03, 0x86, 0xa3, 0xc1, 0x74, 0xd6}, {0x53, 0xdd, 0xb1, 0x97, 0x2c, 0xf2, 0xec, 0x11}
};
std::vector<std::vector<uint8_t>> cts = {
    {0xe0, 0xce, 0x7b, 0xa2, 0xf9, 0x76, 0x51, 0xba}, {0x84, 0xdb, 0x1c, 0xab, 0xc7, 0x88, 0x05, 0xc5},
    {0xc0, 0xdf, 0xa7, 0xb6, 0x5b, 0xbb, 0x73, 0x19}, {0xad, 0x91, 0xc4, 0xbd, 0xbe, 0x33, 0x9f, 0x94},
    {0xdc, 0x0c, 0x4a, 0x20, 0xcb, 0xec, 0xd2, 0xc8}, {0x9c, 0x80, 0x3e, 0xd2, 0xbb, 0xd6, 0x6b, 0x95},
    {0x00, 0x26, 0x65, 0xbd, 0x1c, 0xd9, 0x81, 0x98}, {0x22, 0xf3, 0xa7, 0xe7, 0x91, 0xae, 0x78, 0xb3}
};

void hex_to_bytes(const std::string& hex, std::vector<uint8_t>& bytes) {
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
}

std::vector<uint8_t> unmix(const std::vector<uint8_t>& bs, int step) {
    std::vector<uint8_t> result(8);
    std::rotate_copy(bs.begin(), bs.begin() + (8 - step), bs.end(), result.begin());
    return result;
}

std::vector<uint8_t> unsub(const std::vector<uint8_t>& bs) {
    std::vector<uint8_t> result(bs.size());
    std::transform(bs.begin(), bs.end(), result.begin(), [](uint8_t x) { return SBOX[x]; });
    return result;
}

std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> mix_bytes(const std::vector<uint8_t>& bs, int step) {
    std::vector<uint8_t> result(8);
    std::rotate_copy(bs.begin(), bs.begin() + step, bs.end(), result.begin());
    return result;
}

std::vector<uint8_t> sub_bytes(const std::vector<uint8_t>& bs) {
    std::vector<uint8_t> result(bs.size());
    for (int i = 0; i < 8; i++) result[i] = SBOX[i];
    return result;
}

std::vector<uint8_t> inzip(std::vector<uint8_t> bs, const std::vector<uint8_t>& key, int step) {
    for (int round = 0; round < ROUNDS; ++round) {
        bs = xor_bytes(bs, key);
        bs = sub_bytes(bs);
        bs = mix_bytes(bs, step);
    }
    return bs;
}

void th(int s, int e) {
    for (int b0 = s; b0 < e; ++b0) {
        for (int b1 = 0; b1 < 64; ++b1) {
            for (int b2 = 0; b2 < 64; ++b2) {
                for (int b3 = 0; b3 < 64; ++b3) {
                    for (int b4 = 0; b4 < 64; ++b4) {
                        for (int b5 = 0; b5 < 64; ++b5) {
                            for (int b6 = 0; b6 < 64; ++b6) {
                                for (int b7 = 0; b7 < 64; ++b7) {
                                    std::vector<uint8_t> key = {static_cast<uint8_t>(b0), static_cast<uint8_t>(b1), static_cast<uint8_t>(b2), static_cast<uint8_t>(b3), static_cast<uint8_t>(b4), static_cast<uint8_t>(b5), static_cast<uint8_t>(b6), static_cast<uint8_t>(b7)};
                                    for (int step = 1; step <= 6; ++step) {
                                        bool valid = true;
                                        for (size_t i = 0; i < pts.size(); ++i) {
                                            auto pt = pts[i];
                                            auto ct = cts[i];
                                            auto ct1 = inzip(pt, key, step);
                                            if (std::find(ct.begin(), ct.end(), ct1[i]) == ct.end()) {
                                                valid = false;
                                                break;
                                            }
                                        }
                                        if (valid) {
                                            std::ofstream outFile("answer.txt", std::ios::app);
                                            outFile << "ctfcup{" << std::hex << std::setw(2) << std::setfill('0') << key[0];
                                            for (int j = 1; j < 8; ++j)
                                                outFile << key[j];
                                            outFile << "}\n";
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

int main() {
    /*
    for (const auto& pt : pts) {
        std::vector<uint8_t> bytePt;
        hex_to_bytes(pt, bytePt);
        bpts.push_back(bytePt);
    }
    for (const auto& ct : cts) {
        std::vector<uint8_t> byteCt;
        hex_to_bytes(ct, byteCt);
        bcts.push_back(byteCt);
    }
    */

    std::vector<std::thread> threads;
    std::array<int, 8> steps = {0, 8, 16, 24, 32, 40, 48, 64};
    for (size_t i = 0; i < steps.size() - 1; i++) {
        threads.emplace_back(th, steps[i], steps[i + 1]);
    }
    for (auto& th : threads) th.join();

    return 0;
}