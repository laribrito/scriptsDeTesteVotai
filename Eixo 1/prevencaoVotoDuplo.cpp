/*
 * Teste 1: Prevenção de Voto Duplo e Concorrência na API (Eixo 1)
 *
 * Implementação nativa em C++20 com paralelismo real via std::thread,
 * sincronização por std::barrier e Last-Byte Sync (TCP_NODELAY) sobre sockets POSIX,
 * utilizando OpenSSL 3.x para as 3 camadas criptográficas do Vota-i 2.0.
 *
 * Compilação:
 *   g++ -std=c++20 -O2 -Wall -pthread prevencaoVotoDuplo.cpp -o prevencaoVotoDuplo -lssl -lcrypto
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <barrier>  // IWYU pragma: keep
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

// ==============================================================================
// Configuração direta do ensaio
// ==============================================================================
static constexpr const char* HOST = "127.0.0.1";
static constexpr int PORT = 8000;
static constexpr int NUM_REQUISICOES = 15;
static constexpr const char* SE_KEYS_PATH = "/home/debrito/Programação/votaai-backend/se_keys_info.json";
static constexpr const char* DEFAULT_TOKEN = "SEU_TOKEN_DE_VOTACAO_AQUI";

using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// ==============================================================================
// Utilitários Base64, JSON e Aleatoriedade
// ==============================================================================
static std::string b64_encode(const uint8_t* data, size_t len) {
    std::string out(((len + 2) / 3) * 4 + 1, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(len));
    if (written < 0) throw std::runtime_error("Falha ao codificar Base64.");
    out.resize(static_cast<size_t>(written));
    return out;
}

static std::vector<uint8_t> b64_decode(const std::string& in) {
    std::string clean;
    clean.reserve(in.size());
    for (char c : in) {
        if (c != '\n' && c != '\r' && c != ' ') clean.push_back(c);
    }
    if (clean.empty()) return {};
    std::vector<uint8_t> out((clean.size() / 4) * 3 + 3);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(clean.data()), static_cast<int>(clean.size()));
    if (len < 0) throw std::runtime_error("Falha ao decodificar Base64.");
    if (!clean.empty() && clean.back() == '=') len--;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') len--;
    out.resize(static_cast<size_t>(std::max(0, len)));
    return out;
}

static std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("Falha em RAND_bytes.");
    return buf;
}

static std::string random_hex(size_t n_bytes) {
    static constexpr char hex[] = "0123456789abcdef";
    auto bytes = random_bytes(n_bytes);
    std::string s;
    s.reserve(n_bytes * 2);
    for (uint8_t b : bytes) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0x0F]);
    }
    return s;
}

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

static std::string extract_json_str(const std::string& json, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    std::smatch m;
    if (!std::regex_search(json, m, re)) return "";
    std::string raw = m[1].str();
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            char nxt = raw[++i];
            if (nxt == 'n') out.push_back('\n');
            else if (nxt == 'r') out.push_back('\r');
            else if (nxt == 't') out.push_back('\t');
            else out.push_back(nxt);
        } else {
            out.push_back(raw[i]);
        }
    }
    return out;
}

static size_t skip_json_string(const std::string& s, size_t pos) {
    ++pos;
    while (pos < s.size()) {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            pos += 2;
        } else if (s[pos] == '"') {
            return pos + 1;
        } else {
            ++pos;
        }
    }
    return pos;
}

static std::string extract_json_block(const std::string& json, const std::string& key, char open_ch, char close_ch) {
    std::string needle = "\"" + key + "\"";
    int depth = 0;
    for (size_t i = 0; i < json.size(); ++i) {
        if (json[i] == '"') {
            if (depth <= 1 && json.compare(i, needle.size(), needle) == 0) {
                size_t cur = i + needle.size();
                while (cur < json.size() && (json[cur] == ' ' || json[cur] == '\t' || json[cur] == '\n' || json[cur] == '\r')) ++cur;
                if (cur < json.size() && json[cur] == ':') {
                    ++cur;
                    while (cur < json.size() && (json[cur] == ' ' || json[cur] == '\t' || json[cur] == '\n' || json[cur] == '\r')) ++cur;
                    if (cur < json.size() && json[cur] == open_ch) {
                        int bdepth = 0;
                        size_t start = cur;
                        while (cur < json.size()) {
                            if (json[cur] == '"') {
                                cur = skip_json_string(json, cur);
                                continue;
                            }
                            if (json[cur] == open_ch) bdepth++;
                            else if (json[cur] == close_ch) {
                                bdepth--;
                                if (bdepth == 0) return json.substr(start, cur - start + 1);
                            }
                            ++cur;
                        }
                    }
                }
            }
            i = skip_json_string(json, i) - 1;
            continue;
        }
        if (json[i] == '{' || json[i] == '[') depth++;
        else if (json[i] == '}' || json[i] == ']') depth--;
    }
    return "";
}

static long long extract_json_int(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    int depth = 0;
    for (size_t i = 0; i < json.size(); ++i) {
        if (json[i] == '"') {
            if (depth <= 1 && json.compare(i, needle.size(), needle) == 0) {
                size_t cur = i + needle.size();
                while (cur < json.size() && (json[cur] == ' ' || json[cur] == '\t' || json[cur] == '\n' || json[cur] == '\r')) ++cur;
                if (cur < json.size() && json[cur] == ':') {
                    ++cur;
                    while (cur < json.size() && (json[cur] == ' ' || json[cur] == '\t' || json[cur] == '\n' || json[cur] == '\r')) ++cur;
                    size_t num_start = cur;
                    if (cur < json.size() && json[cur] == '-') ++cur;
                    while (cur < json.size() && std::isdigit(static_cast<unsigned char>(json[cur]))) ++cur;
                    if (cur > num_start) return std::stoll(json.substr(num_start, cur - num_start));
                }
            }
            i = skip_json_string(json, i) - 1;
            continue;
        }
        if (json[i] == '{' || json[i] == '[') depth++;
        else if (json[i] == '}' || json[i] == ']') depth--;
    }
    return -1;
}

static std::vector<std::string> split_json_objects(const std::string& arr_json) {
    std::vector<std::string> items;
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (size_t i = 0; i < arr_json.size(); ++i) {
        if (arr_json[i] == '"') {
            i = skip_json_string(arr_json, i) - 1;
            continue;
        }
        if (arr_json[i] == '{') {
            if (depth == 1) obj_start = i;
            depth++;
        } else if (arr_json[i] == '}') {
            depth--;
            if (depth == 1 && obj_start != std::string::npos) {
                items.push_back(arr_json.substr(obj_start, i - obj_start + 1));
                obj_start = std::string::npos;
            }
        } else if (arr_json[i] == '[') {
            depth++;
        } else if (arr_json[i] == ']') {
            depth--;
        }
    }
    return items;
}

// ==============================================================================
// Criptografia OpenSSL (Chave API RSA1, Chave Dispositivo, X.509, Envelope)
// ==============================================================================
static PKeyPtr carregar_chave_api() {
    std::ifstream ifs(SE_KEYS_PATH);
    if (!ifs) throw std::runtime_error(std::string("Não foi possível abrir ") + SE_KEYS_PATH);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    auto pos = content.find("VotaAI_SecureKey_2");
    if (pos == std::string::npos) throw std::runtime_error("VotaAI_SecureKey_2 não encontrada em se_keys_info.json.");
    std::string b64 = extract_json_str(content.substr(pos), "PublicKeyBase64");
    auto blob = b64_decode(b64);
    if (blob.size() < 24) throw std::runtime_error("Blob RSA1 inválido.");

    auto read_u32_le = [&](size_t off) -> uint32_t {
        return uint32_t(blob[off]) | (uint32_t(blob[off + 1]) << 8) |
               (uint32_t(blob[off + 2]) << 16) | (uint32_t(blob[off + 3]) << 24);
    };
    uint32_t cb_exp = read_u32_le(8);
    uint32_t cb_mod = read_u32_le(12);
    if (24 + cb_exp + cb_mod > blob.size()) throw std::runtime_error("Tamanho de blob RSA1 inconsistente.");

    std::unique_ptr<BIGNUM, decltype(&BN_free)> e_bn(BN_bin2bn(blob.data() + 24, cb_exp, nullptr), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n_bn(BN_bin2bn(blob.data() + 24 + cb_exp, cb_mod, nullptr), BN_free);
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> bld(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);

    OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n_bn.get());
    OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e_bn.get());
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(bld.get()), OSSL_PARAM_free);

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        throw std::runtime_error("Falha ao construir chave RSA pública do backend.");
    }
    return PKeyPtr(raw_pkey, EVP_PKEY_free);
}

static std::string exportar_pub_pem(EVP_PKEY* pkey) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (PEM_write_bio_PUBKEY(bio.get(), pkey) != 1) throw std::runtime_error("Falha ao exportar PEM público.");
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

static std::string gerar_certificado_strongbox(EVP_PKEY* dev_priv, const std::string& challenge) {
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400);
    X509_set_pubkey(cert.get(), dev_priv);

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("StrongBox Test CA"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);

    std::vector<uint8_t> inner = {0x02, 0x01, 0x03, 0x0A, 0x01, 0x02, 0x02, 0x01, 0x04, 0x0A, 0x01, 0x02, 0x04};
    inner.push_back(static_cast<uint8_t>(challenge.size()));
    inner.insert(inner.end(), challenge.begin(), challenge.end());

    std::vector<uint8_t> ext_val = {0x30, static_cast<uint8_t>(inner.size())};
    ext_val.insert(ext_val.end(), inner.begin(), inner.end());

    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> oct(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    ASN1_OCTET_STRING_set(oct.get(), ext_val.data(), static_cast<int>(ext_val.size()));
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1), ASN1_OBJECT_free);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, oct.get()), X509_EXTENSION_free);
    X509_add_ext(cert.get(), ext.get(), -1);

    if (X509_sign(cert.get(), dev_priv, EVP_sha256()) <= 0)
        throw std::runtime_error("Falha ao assinar certificado X.509 StrongBox.");

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(bio.get(), cert.get());
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

static std::string assinar_conteudo(EVP_PKEY* dev_priv, const std::string& content) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t sig_len = 0;
    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, dev_priv) <= 0 ||
        EVP_DigestSign(mdctx.get(), nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(content.data()), content.size()) <= 0)
        throw std::runtime_error("Falha ao inicializar assinatura RSA.");

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(mdctx.get(), sig.data(), &sig_len,
                       reinterpret_cast<const unsigned char*>(content.data()), content.size()) <= 0)
        throw std::runtime_error("Falha ao assinar payload.");
    return b64_encode(sig.data(), sig_len);
}

static std::string cifrar_envelope(EVP_PKEY* api_pub, const std::string& json_payload) {
    auto aes_key = random_bytes(32);
    auto iv = random_bytes(12);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::vector<uint8_t> ciphertext(json_payload.size() + 16);
    int out_len = 0, fin_len = 0;
    uint8_t tag[16];

    if (EVP_EncryptInit_ex(cctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(cctx.get(), nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(cctx.get(), ciphertext.data(), &out_len,
                          reinterpret_cast<const unsigned char*>(json_payload.data()),
                          static_cast<int>(json_payload.size())) != 1 ||
        EVP_EncryptFinal_ex(cctx.get(), ciphertext.data() + out_len, &fin_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        throw std::runtime_error("Falha ao cifrar AES-256-GCM.");
    }
    ciphertext.resize(static_cast<size_t>(out_len + fin_len));

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new(api_pub, nullptr), EVP_PKEY_CTX_free);
    size_t enc_key_len = 0;
    if (EVP_PKEY_encrypt_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(pctx.get(), nullptr, &enc_key_len, aes_key.data(), aes_key.size()) <= 0)
        throw std::runtime_error("Falha ao inicializar criptografia RSA.");

    std::vector<uint8_t> enc_key(enc_key_len);
    if (EVP_PKEY_encrypt(pctx.get(), enc_key.data(), &enc_key_len, aes_key.data(), aes_key.size()) <= 0)
        throw std::runtime_error("Falha ao cifrar chave AES com RSA.");

    std::ostringstream oss;
    oss << "{\"encrypted_payload\":\"" << b64_encode(ciphertext.data(), ciphertext.size())
        << "\",\"encrypted_aes_key\":\"" << b64_encode(enc_key.data(), enc_key_len)
        << "\",\"iv\":\"" << b64_encode(iv.data(), iv.size())
        << "\",\"tag\":\"" << b64_encode(tag, 16) << "\"}";
    return oss.str();
}

static std::string decifrar_resposta(EVP_PKEY* dev_priv, const std::string& raw_body) {
    std::string enc_payload = extract_json_str(raw_body, "encrypted_payload");
    std::string enc_aes_b64 = extract_json_str(raw_body, "encrypted_aes_key");
    std::string iv_b64 = extract_json_str(raw_body, "iv");
    std::string tag_b64 = extract_json_str(raw_body, "tag");
    if (enc_payload.empty() || enc_aes_b64.empty() || iv_b64.empty() || tag_b64.empty())
        return raw_body;

    auto enc_aes = b64_decode(enc_aes_b64);
    auto iv = b64_decode(iv_b64);
    auto ct = b64_decode(enc_payload);
    auto tag = b64_decode(tag_b64);

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new(dev_priv, nullptr), EVP_PKEY_CTX_free);
    size_t aes_len = 0;
    if (EVP_PKEY_decrypt_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_decrypt(pctx.get(), nullptr, &aes_len, enc_aes.data(), enc_aes.size()) <= 0)
        return raw_body;

    std::vector<uint8_t> aes_key(aes_len);
    if (EVP_PKEY_decrypt(pctx.get(), aes_key.data(), &aes_len, enc_aes.data(), enc_aes.size()) <= 0)
        return raw_body;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::vector<uint8_t> plain(ct.size() + 16);
    int out_len = 0, fin_len = 0;
    if (EVP_DecryptInit_ex(cctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(cctx.get(), nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(cctx.get(), plain.data(), &out_len, ct.data(), static_cast<int>(ct.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1 ||
        EVP_DecryptFinal_ex(cctx.get(), plain.data() + out_len, &fin_len) != 1) {
        return raw_body;
    }
    return std::string(reinterpret_cast<const char*>(plain.data()), static_cast<size_t>(out_len + fin_len));
}

// ==============================================================================
// Sockets POSIX + HTTP/1.1 + Last-Byte Sync
// ==============================================================================
static int conectar_tcp() {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(PORT);
    if (getaddrinfo(HOST, port_str.c_str(), &hints, &res) != 0 || !res)
        throw std::runtime_error("Falha ao resolver host.");

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        throw std::runtime_error("Falha ao criar socket.");
    }
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        throw std::runtime_error("Falha ao conectar em " + std::string(HOST) + ":" + port_str);
    }
    freeaddrinfo(res);
    return sock;
}

static void enviar_tudo(int sock, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) throw std::runtime_error("Erro ao enviar dados no socket.");
        sent += static_cast<size_t>(n);
    }
}

static std::pair<int, std::string> ler_resposta_http(int sock) {
    std::string raw;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        raw.append(buf, static_cast<size_t>(n));
    }
    auto hdr_end = raw.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return {0, raw};

    std::string headers = raw.substr(0, hdr_end);
    std::string body = raw.substr(hdr_end + 4);
    int status_code = 0;
    auto sp1 = headers.find(' ');
    if (sp1 != std::string::npos) status_code = std::atoi(headers.c_str() + sp1 + 1);
    return {status_code, body};
}

static std::string montar_http_post(const std::string& path, const std::string& body) {
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << HOST << ":" << PORT << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return req.str();
}

struct DadosCedula {
    std::string id_voto;
    std::string pacote_cifrado;
};

static PKeyPtr carregar_pub_pem(const std::string& pem) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) throw std::runtime_error("Falha ao criar BIO para chave pública da eleição.");
    EVP_PKEY* raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("Falha ao carregar chave pública PEM da eleição.");
    return PKeyPtr(raw, EVP_PKEY_free);
}

static std::string cifrar_voto_rsa(EVP_PKEY* election_pub, const std::string& ballot_json) {
    if (ballot_json.size() > 200) {
        return cifrar_envelope(election_pub, ballot_json);
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new(election_pub, nullptr), EVP_PKEY_CTX_free);
    size_t enc_len = 0;
    if (!pctx || EVP_PKEY_encrypt_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(pctx.get(), nullptr, &enc_len,
                         reinterpret_cast<const unsigned char*>(ballot_json.data()),
                         ballot_json.size()) <= 0) {
        throw std::runtime_error("Falha ao inicializar cifragem RSA da cédula.");
    }
    std::vector<uint8_t> enc(enc_len);
    if (EVP_PKEY_encrypt(pctx.get(), enc.data(), &enc_len,
                         reinterpret_cast<const unsigned char*>(ballot_json.data()),
                         ballot_json.size()) <= 0) {
        throw std::runtime_error("Falha ao cifrar cédula com a chave pública da eleição.");
    }
    return b64_encode(enc.data(), enc_len);
}

static std::string montar_voto_json(const std::string& dec_response) {
    std::string election_block = extract_json_block(dec_response, "election", '{', '}');
    if (election_block.empty()) {
        throw std::runtime_error("Objeto 'election' ausente na resposta de /api/vote/request/.");
    }
    long long election_id = extract_json_int(election_block, "id");
    if (election_id < 0) {
        throw std::runtime_error("ID da eleição ausente na resposta de /api/vote/request/.");
    }
    std::string questions_block = extract_json_block(election_block, "questions", '[', ']');
    auto question_objs = split_json_objects(questions_block);
    if (question_objs.empty()) {
        throw std::runtime_error("Lista 'questions' vazia na resposta de /api/vote/request/.");
    }

    std::ostringstream choices;
    choices << "{";
    bool first_choice = true;
    for (const auto& q_obj : question_objs) {
        long long q_id = extract_json_int(q_obj, "id");
        std::string opts_block = extract_json_block(q_obj, "options", '[', ']');
        auto opt_objs = split_json_objects(opts_block);
        if (q_id < 0 || opt_objs.empty()) continue;

        long long fallback_opt_id = -1;
        long long preferred_opt_id = -1;
        for (const auto& opt_obj : opt_objs) {
            long long opt_id = extract_json_int(opt_obj, "id");
            if (opt_id < 0) continue;
            if (fallback_opt_id < 0) fallback_opt_id = opt_id;
            std::string label = extract_json_str(opt_obj, "label");
            if (label != "Branco" && label != "Nulo") {
                preferred_opt_id = opt_id;
                break;
            }
        }
        long long chosen_opt_id = (preferred_opt_id >= 0) ? preferred_opt_id : fallback_opt_id;
        if (chosen_opt_id < 0) continue;

        if (!first_choice) choices << ",";
        choices << "\"" << q_id << "\":" << chosen_opt_id;
        first_choice = false;
    }
    choices << "}";
    if (first_choice) {
        throw std::runtime_error("Nenhuma opção válida encontrada para montar a cédula.");
    }

    std::ostringstream ballot;
    ballot << "{\"election_id\":" << election_id << ",\"choices\":" << choices.str() << "}";
    return ballot.str();
}

static DadosCedula solicitar_cedula(EVP_PKEY* api_pub, EVP_PKEY* dev_priv, const std::string& dev_pub_pem, const std::string& token) {
    std::string nonce = "nonce-req-" + random_hex(6);
    std::string cert = gerar_certificado_strongbox(dev_priv, nonce);
    std::ostringstream payload;
    payload << "{\"token\":\"" << json_escape(token)
            << "\",\"machine_public_key\":\"" << json_escape(dev_pub_pem)
            << "\",\"attestation_certificates\":[\"" << json_escape(cert)
            << "\"],\"nonce\":\"" << nonce << "\"}";

    std::string http_req = montar_http_post("/api/vote/request/", cifrar_envelope(api_pub, payload.str()));
    int sock = conectar_tcp();
    enviar_tudo(sock, http_req.data(), http_req.size());
    auto [code, raw_body] = ler_resposta_http(sock);
    close(sock);

    std::string dec = decifrar_resposta(dev_priv, raw_body);
    if (code != 200) throw std::runtime_error("Erro em /api/vote/request/ (HTTP " + std::to_string(code) + "): " + dec);
    std::string id_voto = extract_json_str(dec, "id_voto");
    if (id_voto.empty()) throw std::runtime_error("id_voto ausente na resposta: " + dec);

    std::string election_block = extract_json_block(dec, "election", '{', '}');
    std::string election_pub_pem = extract_json_str(election_block, "public_key");
    if (election_pub_pem.empty()) throw std::runtime_error("public_key da eleição ausente na resposta: " + dec);

    auto election_pub = carregar_pub_pem(election_pub_pem);
    std::string ballot_json = montar_voto_json(dec);
    std::string pacote_cifrado = cifrar_voto_rsa(election_pub.get(), ballot_json);
    return {id_voto, pacote_cifrado};
}

struct ResultadoReq {
    int id = 0;
    int status_code = 0;
    double offset_us = 0.0;
    double latency_ms = 0.0;
    std::string body;
};

int main(int argc, char* argv[]) {
    bool dry_run = (argc > 1 && std::string(argv[1]) == "--dry-run");
    std::string token = (argc > 1 && !dry_run) ? argv[1] : DEFAULT_TOKEN;

    if (!dry_run && token == DEFAULT_TOKEN) {
        std::cerr << "Uso: " << argv[0] << " <TOKEN_DE_VOTACAO>  (ou --dry-run)\n";
        return 2;
    }

    auto api_pub = carregar_chave_api();
    PKeyPtr dev_priv(EVP_RSA_gen(2048), EVP_PKEY_free);
    if (!dev_priv) throw std::runtime_error("Falha ao gerar chave RSA-2048 do dispositivo.");
    std::string dev_pub_pem = exportar_pub_pem(dev_priv.get());

    if (dry_run) {
        std::string cert = gerar_certificado_strongbox(dev_priv.get(), "dry-run-challenge");
        std::string env = cifrar_envelope(api_pub.get(), "{\"token\":\"dry\",\"machine_public_key\":\"" + json_escape(dev_pub_pem) + "\"}");
        std::cout << "[DRY-RUN C++20] Chave API carregada, certificado StrongBox (" << cert.size()
                  << " bytes) e envelope híbrido (" << env.size() << " bytes) gerados com sucesso.\n";
        return 0;
    }

    DadosCedula cedula = solicitar_cedula(api_pub.get(), dev_priv.get(), dev_pub_pem, token);
    std::string content = "{\"id_voto\":\"" + json_escape(cedula.id_voto) + "\",\"pacote_cifrado\":\"" + json_escape(cedula.pacote_cifrado) + "\"}";
    std::string sig = assinar_conteudo(dev_priv.get(), content);

    std::vector<std::string> pacotes_http(NUM_REQUISICOES);
    for (int i = 0; i < NUM_REQUISICOES; ++i) {
        std::ostringstream payload;
        payload << "{\"token\":\"" << json_escape(token)
                << "\",\"machine_public_key\":\"" << json_escape(dev_pub_pem)
                << "\",\"content\":\"" << json_escape(content)
                << "\",\"id_voto\":\"" << json_escape(cedula.id_voto)
                << "\",\"nonce\":\"nonce-cast-" << i + 1 << "-" << random_hex(5)
                << "\",\"signature\":\"" << sig << "\"}";
        pacotes_http[i] = montar_http_post("/api/vote/cast/", cifrar_envelope(api_pub.get(), payload.str()));
    }

    std::barrier sync_point(NUM_REQUISICOES);
    std::vector<ResultadoReq> resultados(NUM_REQUISICOES);
    std::vector<std::thread> threads;
    std::mutex t0_mtx;
    std::chrono::steady_clock::time_point t_first{};
    bool t0_set = false;

    for (int i = 0; i < NUM_REQUISICOES; ++i) {
        threads.emplace_back([&, i]() {
            ResultadoReq res;
            res.id = i + 1;
            try {
                const std::string& pkt = pacotes_http[i];
                int sock = conectar_tcp();
                // Last-Byte Sync: envia todo o HTTP menos o último byte '}' antes da barreira
                enviar_tudo(sock, pkt.data(), pkt.size() - 1);

                sync_point.arrive_and_wait();

                auto t_send = std::chrono::steady_clock::now();
                enviar_tudo(sock, &pkt.back(), 1);
                {
                    std::lock_guard<std::mutex> lk(t0_mtx);
                    if (!t0_set) {
                        t_first = t_send;
                        t0_set = true;
                    }
                    res.offset_us = std::chrono::duration<double, std::micro>(t_send - t_first).count();
                }

                auto [code, raw_body] = ler_resposta_http(sock);
                auto t_done = std::chrono::steady_clock::now();
                close(sock);

                res.status_code = code;
                res.latency_ms = std::chrono::duration<double, std::milli>(t_done - t_send).count();
                res.body = decifrar_resposta(dev_priv.get(), raw_body);
            } catch (const std::exception& ex) {
                res.body = ex.what();
            }
            resultados[i] = std::move(res);
        });
    }
    for (auto& t : threads) t.join();

    double max_offset_us = 0.0;
    int aceitas = 0, rejeitadas = 0, inesperadas = 0;
    for (const auto& r : resultados) {
        max_offset_us = std::max(max_offset_us, r.offset_us);
        bool confirmada = (r.status_code == 200 || r.status_code == 201) &&
                          r.body.find("CONFIRMED") != std::string::npos;
        bool erro_esperado = (r.status_code == 400 || r.status_code == 403 || r.status_code == 409 ||
                              r.status_code == 423 || r.status_code == 429);
        if (confirmada) aceitas++;
        else if (erro_esperado) rejeitadas++;
        else inesperadas++;
    }

    std::cout << "Disparadas: " << NUM_REQUISICOES << " | Janela de disparo: "
              << (max_offset_us / 1000.0) << " ms (" << max_offset_us << " us)\n"
              << "Aceitas (200 CONFIRMED): " << aceitas
              << " | Rejeitadas (4xx): " << rejeitadas
              << " | Outras/5xx: " << inesperadas << "\n";

    for (const auto& r : resultados) {
        std::cout << "  Req " << r.id << ": +" << r.offset_us << " us | HTTP " << r.status_code
                  << " (" << r.latency_ms << " ms) -> " << r.body << "\n";
    }

    bool aprovado = (aceitas == 1 && rejeitadas == NUM_REQUISICOES - 1 && inesperadas == 0);
    std::cout << "\nResultado: " << (aprovado ? "APROVADO" : "REPROVADO") << "\n";
    return aprovado ? 0 : 1;
}
