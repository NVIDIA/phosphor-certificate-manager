#include "config.h"

#include "uefiSignatureOwnerIntf.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::certs::internal::UefiSignatureOwnerIntf,
                     classVersion);

namespace phosphor::certs
{

namespace internal
{

/** @brief Function required by Cereal to perform serialization.
 *
 *  @tparam Archive - Cereal archive type (binary in this case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[in] owner- const reference to UefiSignatureOwnerIntf
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void save(Archive& archive, const UefiSignatureOwnerIntf& owner,
          const std::uint32_t /*version*/)
{
    archive(owner.uuid());
}

/** @brief Function required by Cereal to perform deserialization.
 *
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[out] owner - UefiSignatureOwnerIntf to be read
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void load(Archive& archive, UefiSignatureOwnerIntf& owner,
          const std::uint32_t /*version*/)
{
    std::string uuid{};
    archive(uuid);
    owner.UUID::uuid(uuid);
}

UefiSignatureOwnerIntf::~UefiSignatureOwnerIntf()
{
    if (!ownerFilePath.empty())
    {
        fs::remove(ownerFilePath);
    }
}

UefiSignatureOwnerIntf::UefiSignatureOwnerIntf(sdbusplus::bus::bus& bus,
                                               const std::string& objPath,
                                               const std::string& filePath) :
    UUID(bus, objPath.c_str()),
    ownerFilePath(filePath)
{
    if (!ownerFilePath.empty())
    {
        try
        {
            if (fs::exists(ownerFilePath) == false)
            {
                return;
            }
            std::ifstream is(ownerFilePath.c_str(),
                             std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(*this);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to load uefiSignatureOwner",
                            entry("ERR=%s", e.what()));
            elog<InternalFailure>();
        }
    }
}

std::string UefiSignatureOwnerIntf::uuid(std::string value)
{
    value = UUID::uuid(value);
    if (!ownerFilePath.empty())
    {
        try
        {
            std::ofstream os(ownerFilePath.c_str(),
                             std::ios::binary | std::ios::out);
            cereal::BinaryOutputArchive oarchive(os);
            oarchive(*this);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to save uefiSignatureOwner",
                            entry("ERR=%s", e.what()));
            elog<InternalFailure>();
        }
    }
    return value;
}

} // namespace internal
} // namespace phosphor::certs
