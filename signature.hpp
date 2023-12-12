#pragma once

#include "certificate.hpp"
#include "uefiSignatureOwnerIntf.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <phosphor-logging/elog.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <xyz/openbmc_project/BIOSConfig/SecureBootDatabase/Signature/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor::certs
{

using SignatureInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::BIOSConfig::SecureBootDatabase::server::
        Signature,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using SignatureFormat = sdbusplus::xyz::openbmc_project::BIOSConfig::
    SecureBootDatabase::server::Signature::SignatureFormat;

class SigManager; // Forward declaration for Signature Manager.

/** @class Signature
 *  @brief OpenBMC Signature entry implementation.
 */
class Signature : public SignatureInterface
{
  public:
    using SignatureInterface::format;
    using SignatureInterface::signatureString;

    Signature() = delete;
    Signature(const Signature&) = delete;
    Signature& operator=(const Signature&) = delete;
    Signature(Signature&&) = delete;
    Signature& operator=(Signature&&) = delete;

    /** @brief Constructor for the Signature Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] type - Type of the certificate
     *  @param[in] installPath - Path of the signature to install
     *  @param[in] parent - The manager that owns the signature
     *  @param[in] sigString - SignatrueString value
     *  @param[in] sigFormat - Formate enum of signature
     */
    Signature(sdbusplus::bus::bus& bus, const std::string& objPath,
              CertificateType type, const std::string& installPath,
              SigManager& parent, const std::string sigString = "",
              const SignatureFormat sigFormat = SignatureFormat::Unspecified);

    /** @brief Delete signature file
     */
    void deleteFile();

    /**
     * @brief Check if provided signature is the same as the current one.
     *
     * @param[in] sigString - Signatrue string.
     *
     * @return Checking result. Return true if signatures are the same,
     *         false if not.
     */
    bool isSame(const std::string& sigString);

    /**
     * @brief Load signature from file.
     */
    void loadFromFile();

    /**
     * @brief Save signature to file.
     */
    void saveToFile();

    /**
     * @brief Delete the signature
     */
    void delete_() override;

    /**
     * @brief Set DBus SignatureStirng, and save to file
     */
    std::string signatureString(std::string val) override;

    /**
     * @brief Set DBus type, and save to file
     */
    SignatureFormat format(SignatureFormat val) override;

    /**
     * @brief Get object Path
     *
     * @return Object Path.
     */
    std::string getObjectPath() const;

  private:
    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate / signature */
    [[maybe_unused]] CertificateType certType;

    /** @brief Stores signature file path */
    std::string signatureFilePath;

    /** @brief Signature file installation path */
    std::string signatureInstallPath;

    /** @brief Reference to Signature Manager */
    SigManager& manager;

    /** @brief Interface of UefiSignatureOwner */
    std::unique_ptr<internal::UefiSignatureOwnerIntf> ownerIntf;
};

} // namespace phosphor::certs
