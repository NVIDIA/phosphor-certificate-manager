#pragma once

#include "signature.hpp"

#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/BIOSConfig/SecureBootDatabase/AddSignature/server.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace phosphor::certs
{

namespace internal
{
using sigManagerInterface =
    sdbusplus::server::object_t<sdbusplus::xyz::openbmc_project::BIOSConfig::
                                    SecureBootDatabase::server::AddSignature>;
}

class SigManager : public internal::sigManagerInterface
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor is not possible due to member
     *           reference
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - copy
     *         - Destructor.
     */
    SigManager() = delete;
    SigManager(const SigManager&) = delete;
    SigManager& operator=(const SigManager&) = delete;
    SigManager(SigManager&&) = delete;
    SigManager& operator=(SigManager&&) = delete;
    ~SigManager();

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] event - sd event handler.
     *  @param[in] path - Path to attach at.
     *  @param[in] type - Type of the signature.
     *  @param[in] installPath - Signature installation path.
     */
    SigManager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
               const char* path, CertificateType type,
               const std::string& installPath);

    /** @brief Implementation for Add signature
     *
     *  @param[in] sigString - The string of for the signature.
     *  @param[in] format - The format of the signature.
     *
     *  @return Signature object path.
     */
    std::string add(const std::string sigString,
                    const SignatureFormat format) override;

    /** @brief Implementation for DeleteAll
     *  Delete all objects in the collection.
     */
    void deleteAll();

    /** @brief Delete the signature.
     */
    void deleteSignature(const Signature* const signature);

    /** @brief Get reference to signatures' collection
     *
     *  @return Reference to signatures' collection
     */
    std::vector<std::unique_ptr<Signature>>& getSignatures();

  private:
    /** @brief Load signature
     *  Load signature and create signature object
     */
    void createSignatures();

    /** @brief Check if provided signature is unique across all signatures
     * on the internal list.
     *  @param[in] SignatureString - The string of for the signature for
     * uniqueness check.
     *  @return     Checking result. True if signature is unique, false if
     * not.
     */
    bool isSignatureUnique(const std::string& signatureString);

    /** @brief Allocate a signature ID.
     *  @param[in] id - The designated ID to allocated. 0 if no designated.
     *  @return Allocated signature ID.
     */
    uint64_t allocId(uint64_t id = 0);

    /** @brief Release a signature ID.
     *  @param[in] id - ID to be released.
     */
    void releaseId(uint64_t id);

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    // sdevent Event handle
    [[maybe_unused]] sdeventplus::Event& event;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate / signature **/
    CertificateType certType;

    /** @brief Signature file installation path **/
    std::string sigInstallPath;

    /** @brief Collection of pointers to signature */
    std::vector<std::unique_ptr<Signature>> installedSignatures;

    /** @brief Signature ID pool */
    uint64_t sigIdCounter = 1;

    /** @brief Unused Signature ID pool */
    std::set<uint64_t> sigIdUnused;
};
} // namespace phosphor::certs
