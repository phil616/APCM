#pragma once

#include <QByteArray>

#include <cstddef>

namespace certmgr::persistence {

class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(qsizetype size);
    explicit SecureBuffer(const QByteArray &source);
    ~SecureBuffer();
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;

    [[nodiscard]] unsigned char *data() { return data_; }
    [[nodiscard]] const unsigned char *data() const { return data_; }
    [[nodiscard]] qsizetype size() const { return size_; }
    [[nodiscard]] bool isEmpty() const { return size_ == 0; }
    [[nodiscard]] QByteArray copy() const;
    void clear();

private:
    unsigned char *data_{nullptr};
    qsizetype size_{0};
};

} // namespace certmgr::persistence

