#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <OleAuto.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <wrl/client.h>

#include <QString>

#include <memory>
#include <utility>

namespace certmgr::platform::windows {

class CertStoreHandle {
public:
    CertStoreHandle() = default;
    explicit CertStoreHandle(HCERTSTORE value) : value_(value) {}
    ~CertStoreHandle() { reset(); }
    CertStoreHandle(const CertStoreHandle &) = delete;
    CertStoreHandle &operator=(const CertStoreHandle &) = delete;
    CertStoreHandle(CertStoreHandle &&other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    CertStoreHandle &operator=(CertStoreHandle &&other) noexcept
    {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }
    [[nodiscard]] HCERTSTORE get() const { return value_; }
    [[nodiscard]] explicit operator bool() const { return value_ != nullptr; }
    void reset(HCERTSTORE replacement = nullptr)
    {
        if (value_) CertCloseStore(value_, 0);
        value_ = replacement;
    }

private:
    HCERTSTORE value_{nullptr};
};

struct CertContextDeleter {
    void operator()(const CERT_CONTEXT *context) const
    {
        if (context) CertFreeCertificateContext(context);
    }
};
using CertContextPtr = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

class NCryptKeyHandle {
public:
    NCryptKeyHandle() = default;
    explicit NCryptKeyHandle(NCRYPT_KEY_HANDLE value) : value_(value) {}
    ~NCryptKeyHandle() { reset(); }
    NCryptKeyHandle(const NCryptKeyHandle &) = delete;
    NCryptKeyHandle &operator=(const NCryptKeyHandle &) = delete;
    NCryptKeyHandle(NCryptKeyHandle &&other) noexcept : value_(std::exchange(other.value_, 0)) {}
    NCryptKeyHandle &operator=(NCryptKeyHandle &&other) noexcept
    {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, 0);
        }
        return *this;
    }
    [[nodiscard]] NCRYPT_KEY_HANDLE get() const { return value_; }
    void reset(NCRYPT_KEY_HANDLE replacement = 0)
    {
        if (value_) NCryptFreeObject(value_);
        value_ = replacement;
    }

private:
    NCRYPT_KEY_HANDLE value_{0};
};

class LocalAllocPtr {
public:
    explicit LocalAllocPtr(void *value = nullptr) : value_(value) {}
    ~LocalAllocPtr() { if (value_) LocalFree(value_); }
    LocalAllocPtr(const LocalAllocPtr &) = delete;
    LocalAllocPtr &operator=(const LocalAllocPtr &) = delete;
    [[nodiscard]] void *get() const { return value_; }

private:
    void *value_;
};

template <typename T>
using ComPtr = Microsoft::WRL::ComPtr<T>;

class BStr {
public:
    BStr() = default;
    explicit BStr(const QString &value) : value_(SysAllocStringLen(
                                                    reinterpret_cast<const OLECHAR *>(value.utf16()),
                                                    static_cast<UINT>(value.size()))) {}
    ~BStr() { if (value_) SysFreeString(value_); }
    BStr(const BStr &) = delete;
    BStr &operator=(const BStr &) = delete;
    [[nodiscard]] BSTR get() const { return value_; }
    [[nodiscard]] BSTR *put()
    {
        if (value_) SysFreeString(value_);
        value_ = nullptr;
        return &value_;
    }
    [[nodiscard]] QString toQString() const
    {
        return value_ ? QString::fromWCharArray(value_, static_cast<qsizetype>(SysStringLen(value_))) : QString{};
    }

private:
    BSTR value_{nullptr};
};

} // namespace certmgr::platform::windows
