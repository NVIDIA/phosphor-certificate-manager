#pragma once

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/UUID/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace phosphor::certs
{

namespace internal
{

namespace
{
namespace fs = std::filesystem;
using ::phosphor::logging::commit;
using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;

using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using ::sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedReason =
    ::phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using sdbusplus::xyz::openbmc_project::Common::server::UUID;
} // namespace

class UefiSignatureOwnerIntf : public UUID
{
  public:
    using UUID::uuid;

    UefiSignatureOwnerIntf() = delete;
    UefiSignatureOwnerIntf(const UefiSignatureOwnerIntf&) = delete;
    UefiSignatureOwnerIntf& operator=(const UefiSignatureOwnerIntf&) = delete;
    UefiSignatureOwnerIntf(UefiSignatureOwnerIntf&&) = delete;
    UefiSignatureOwnerIntf& operator=(UefiSignatureOwnerIntf&&) = delete;
    virtual ~UefiSignatureOwnerIntf();

    /** @brief Constructor for the UefiSignatureOwnerIntf Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] filePath - Path of the UefiSignatureOwner to store
     */
    UefiSignatureOwnerIntf(sdbusplus::bus::bus& bus, const std::string& objPath,
                           const std::string& filePath);

    std::string uuid(std::string value) override;

  private:
    std::string ownerFilePath;
};

} // namespace internal
} // namespace phosphor::certs
