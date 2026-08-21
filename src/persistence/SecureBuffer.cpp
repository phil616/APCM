#include "SecureBuffer.h"

#include <sodium.h>

#include <cstring>
#include <utility>

namespace certmgr::persistence {

SecureBuffer::SecureBuffer(const qsizetype size) : size_(size)
{
    if (size_ <= 0) return;
    data_ = static_cast<unsigned char *>(sodium_malloc(static_cast<size_t>(size_)));
    if (!data_) throw std::bad_alloc();
    sodium_mlock(data_, static_cast<size_t>(size_));
    sodium_memzero(data_, static_cast<size_t>(size_));
}

SecureBuffer::SecureBuffer(const QByteArray &source) : SecureBuffer(source.size())
{
    if (data_) std::memcpy(data_, source.constData(), static_cast<size_t>(size_));
}

SecureBuffer::~SecureBuffer() { clear(); }

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    if (this != &other) {
        clear();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

QByteArray SecureBuffer::copy() const
{
    return data_ ? QByteArray(reinterpret_cast<const char *>(data_), size_) : QByteArray{};
}

void SecureBuffer::clear()
{
    if (!data_) return;
    sodium_memzero(data_, static_cast<size_t>(size_));
    sodium_munlock(data_, static_cast<size_t>(size_));
    sodium_free(data_);
    data_ = nullptr;
    size_ = 0;
}

} // namespace certmgr::persistence

