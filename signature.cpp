#include "config.h"

#include "signature.hpp"

#include "signature_manager.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <utility>
#include <vector>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::certs::Signature, CLASS_VERSION);

namespace phosphor::certs
{

namespace
{
namespace fs = std::filesystem;
using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;
using InvalidCertificateError =
    ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::phosphor::logging::xyz::openbmc_project::Certs::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

} // namespace

/** @brief Function required by Cereal to perform serialization.
 *
 *  @tparam Archive - Cereal archive type (binary in this case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[in] signature- const reference to Signature
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void save(Archive& archive, const Signature& signature,
          const std::uint32_t /*version*/)
{
    archive(signature.signatureString(),
            signature.convertSignatureFormatToString(signature.format()));
}

/** @brief Function required by Cereal to perform deserialization.
 *
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[out] signature - Signature to be read
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void load(Archive& archive, Signature& signature,
          const std::uint32_t /*version*/)
{
    std::string sigString{};
    std::string sigFormat{};

    archive(sigString, sigFormat);

    signature.signatureString(sigString);
    signature.format(signature.convertSignatureFormatFromString(sigFormat));
}

Signature::Signature(sdbusplus::bus::bus& bus, const std::string& objPath,
                     CertificateType type, const std::string& installPath,
                     SigManager& parent, const std::string sigString,
                     const SignatureFormat sigFormat) :
    SignatureInterface(bus, objPath.c_str(),
                       SignatureInterface::action::defer_emit),
    objectPath(objPath), certType(type), signatureInstallPath(installPath),
    manager(parent)
{
    // Generate signature file path
    signatureFilePath =
        signatureInstallPath + "/" + fs::path(objectPath).filename().c_str();

    loadFromFile();

    if (!sigString.empty())
    {
        signatureString(sigString);
    }

    if (sigFormat != SignatureFormat::Unspecified)
    {
        format(sigFormat);
    }

    ownerIntf = std::make_unique<internal::UefiSignatureOwnerIntf>(
        bus, objectPath, signatureFilePath + ".owner");
    this->emit_object_added();
}

void Signature::deleteFile()
{
    if (!fs::remove(signatureFilePath))
    {
        log<level::INFO>("Signature file not found!",
                         entry("PATH=%s", signatureFilePath.c_str()));
    }
}

bool Signature::isSame(const std::string& sigString)
{
    return SignatureInterface::signatureString() == sigString;
}

void Signature::loadFromFile()
{
    if (!signatureFilePath.empty())
    {
        try
        {
            if (fs::exists(signatureFilePath) == false)
            {
                return;
            }
            std::ifstream is(signatureFilePath.c_str(),
                             std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(*this);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to load signature",
                            entry("ERR=%s", e.what()));
            elog<InternalFailure>();
        }
    }
}

void Signature::saveToFile()
{
    if (!signatureFilePath.empty())
    {
        try
        {
            std::ofstream os(signatureFilePath.c_str(),
                             std::ios::binary | std::ios::out);
            cereal::BinaryOutputArchive oarchive(os);
            oarchive(*this);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to save signature",
                            entry("ERR=%s", e.what()));
            elog<InternalFailure>();
        }
    }
}

void Signature::delete_()
{
    manager.deleteSignature(this);
}

std::string Signature::signatureString(std::string val)
{
    auto ret = SignatureInterface::signatureString(val);
    saveToFile();
    return ret;
}

SignatureFormat Signature::format(SignatureFormat val)
{
    auto ret = SignatureInterface::format(val);
    saveToFile();
    return ret;
}

std::string Signature::getObjectPath() const
{
    return objectPath;
}

} // namespace phosphor::certs
