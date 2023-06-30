#include "config.h"

#include "signature_manager.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdeventplus/source/base.hpp>
#include <sdeventplus/source/child.hpp>
#include <utility>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certs
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

using ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using ::sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedReason =
    ::phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using InvalidCertificateReason = ::phosphor::logging::xyz::openbmc_project::
    Certs::InvalidCertificate::REASON;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument =
    ::phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

} // namespace

SigManager::SigManager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                       const char* path, CertificateType type,
                       const std::string& installPath) :
    internal::sigManagerInterface(bus, path),
    bus(bus), event(event), objectPath(path), certType(type),
    sigInstallPath(std::move(installPath))
{
    try
    {
        // Create signature directory if not existing.
        // Set correct signature directory permissions.
        fs::path sigDirectory = sigInstallPath;
        try
        {
            if (!fs::exists(sigDirectory))
            {
                fs::create_directories(sigDirectory);
            }

            auto permission = fs::perms::owner_read | fs::perms::owner_write |
                              fs::perms::owner_exec;
            fs::permissions(sigDirectory, permission,
                            fs::perm_options::replace);
        }
        catch (const fs::filesystem_error& e)
        {
            log<level::ERR>("Failed to create directory",
                            entry("ERR=%s", e.what()),
                            entry("DIRECTORY=%s", sigDirectory.c_str()));
            report<InternalFailure>();
        }

        // restore any existing signature
        createSignatures();
    }
    catch (const std::exception& ex)
    {
        log<level::ERR>("Error in signature manager constructor",
                        entry("ERROR_STR=%s", ex.what()));
    }
}

SigManager::~SigManager()
{
    installedSignatures.clear();
    sigIdUnused.clear();
    sigIdCounter = 1;
}

std::string SigManager::add(const std::string sigString,
                            const SignatureFormat format)
{
    std::string sigObjectPath;
    if (isSignatureUnique(sigString))
    {
        auto signatureId = allocId();
        sigObjectPath =
            objectPath + "/signature/" + std::to_string(signatureId);
        try
        {
            installedSignatures.emplace_back(std::make_unique<Signature>(
                bus, sigObjectPath, certType, sigInstallPath, *this, sigString,
                format));
        }
        catch (const std::exception& ex)
        {
            log<level::ERR>("Error in signature constructor",
                            entry("ERROR_STR=%s", ex.what()));
            releaseId(signatureId);
        }
    }
    else
    {
        elog<NotAllowed>(NotAllowedReason("Signature already exist"));
    }

    return sigObjectPath;
}

void SigManager::deleteAll()
{
    for (auto it = installedSignatures.begin(); it != installedSignatures.end();
         it++)
    {
        (*it)->deleteFile();
    }
    installedSignatures.clear();
    sigIdUnused.clear();
    sigIdCounter = 1;
}

void SigManager::deleteSignature(const Signature* const signature)
{
    std::vector<std::unique_ptr<Signature>>::iterator const& sigIt =
        std::find_if(installedSignatures.begin(), installedSignatures.end(),
                     [signature](std::unique_ptr<Signature> const& sig) {
                         return (sig.get() == signature);
                     });
    if (sigIt != installedSignatures.end())
    {
        auto signatureId =
            std::stoull(fs::path(signature->getObjectPath()).filename());
        releaseId(signatureId);
        (*sigIt)->deleteFile();
        installedSignatures.erase(sigIt);
    }
    else
    {
        log<level::ERR>("Signature does not exist",
                        entry("ID=%s", signature->signatureString().c_str()));
        elog<InternalFailure>();
    }
}

std::vector<std::unique_ptr<Signature>>& SigManager::getSignatures()
{
    return installedSignatures;
}

void SigManager::createSignatures()
{
    auto sigObjectPath = objectPath + "/signature/";

    // Check whether install path is a directory.
    if (!fs::is_directory(sigInstallPath))
    {
        log<level::ERR>("Signature installation path exists and it is "
                        "not a directory");
        elog<InternalFailure>();
        return;
    }

    for (auto& path : fs::directory_iterator(sigInstallPath))
    {
        try
        {
            // Assume here any regular file without extenstion name located in
            // signature directory contains signature body.
            if (fs::is_regular_file(path))
            {
                if (!path.path().extension().empty())
                {
                    continue;
                }
                auto signatureId = std::stoull(path.path().filename());
                allocId(signatureId);
                try
                {
                    installedSignatures.emplace_back(
                        std::make_unique<Signature>(
                            bus, sigObjectPath + std::to_string(signatureId),
                            certType, sigInstallPath, *this));
                }
                catch (const std::exception& ex)
                {
                    log<level::ERR>("Error in signature constructor",
                                    entry("ERROR_STR=%s", ex.what()));
                    releaseId(signatureId);
                }
            }
        }
        catch (const InternalFailure& e)
        {
            report<InternalFailure>();
        }
        catch (const InvalidCertificate& e)
        {
            report<InvalidCertificate>(InvalidCertificateReason(
                "Existing certificate file is corrupted"));
        }
        catch (const std::invalid_argument& e)
        {
            report<InternalFailure>();
        }
    }
}

bool SigManager::isSignatureUnique(const std::string& sigString)
{
    if (std::any_of(installedSignatures.begin(), installedSignatures.end(),
                    [&sigString](std::unique_ptr<Signature> const& sig) {
                        return sig->isSame(sigString);
                    }))
    {
        return false;
    }
    else
    {
        return true;
    }
}

uint64_t SigManager::allocId(uint64_t id)
{
    // Have designated ID
    if (id != 0)
    {
        // Update the Unused IDs
        for (; sigIdCounter <= id; sigIdCounter++)
        {
            sigIdUnused.insert(sigIdCounter);
        }
        sigIdUnused.erase(id);
        return id;
    }

    // No designated ID
    if (!sigIdUnused.empty())
    {
        id = *sigIdUnused.begin();
        sigIdUnused.erase(id);
        return id;
    }
    else
    {
        return sigIdCounter++;
    }
}

void SigManager::releaseId(uint64_t id)
{
    sigIdUnused.insert(id);
}

} // namespace phosphor::certs
