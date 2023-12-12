project(
    'phosphor-certificate-manager',
    'cpp',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++23',
        'warning_level=3',
        'werror=true',
    ],
    meson_version: '>=1.1.1',
)

cpp = meson.get_compiler('cpp')

sdbusplus_dep = dependency('sdbusplus')
sdeventplus_dep = dependency('sdeventplus')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')

cli11_dep = dependency('cli11', required: false)
has_cli11 = meson.get_compiler('cpp').has_header_symbol(
  'CLI/CLI.hpp',
  'CLI::App',
  dependencies: cli11_dep,
  required: false)
if not has_cli11
  cli11_proj = subproject('cli11', required: false)
  assert(cli11_proj.found(), 'CLI11 is required')
  cli11_dep = cli11_proj.get_variable('CLI11_dep')
endif

systemd_dep = dependency('systemd')
openssl_dep = dependency('openssl')

# Get Cereal dependency.
cereal_dep = dependency('cereal', required: false)
has_cereal = cpp.has_header_symbol(
    'cereal/cereal.hpp',
    'cereal::specialize',
    dependencies: cereal_dep,
    required: false)
if not has_cereal
    cereal_opts = import('cmake').subproject_options()
    cereal_opts.add_cmake_defines({'BUILD_TESTS': 'OFF'})
    cereal_proj = import('cmake').subproject(
        'cereal',
        options: cereal_opts,
        required: false)
    assert(cereal_proj.found(), 'cereal is required')
    cereal_dep = cereal_proj.dependency('cereal')
endif

config_data = configuration_data()
config_data.set(
    'authority_limit',
     get_option('authority-limit')
)
config_data.set(
    'authorities_list_name',
     get_option('authorities-list-name')
)

config_data.set(
    'classVersion',
    1,
    description : 'Class version to register with Cereal.'
)

if not get_option('allow-expired').disabled()
  config_data.set('allow_expired', 'true')
else
  config_data.set('allow_expired', 'false')
endif

configure_file(
    input: 'config.h.in',
    output: 'config.h',
    configuration: config_data
)

phosphor_certificate_deps = [
    openssl_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    sdeventplus_dep,
    cli11_dep,
]

cert_manager_lib = static_library(
    'phosphor-certificate-manager',
    [
        'argument.cpp',
        'certificate.cpp',
        'certs_manager.cpp',
        'csr.cpp',
        'watch.cpp',
        'x509_utils.cpp',
        'signature.cpp',
        'signature_manager.cpp',
        'uefiSignatureOwnerIntf.cpp',
    ],
    dependencies: phosphor_certificate_deps,
)

cert_manager_dep = declare_dependency(
    link_with: cert_manager_lib,
    dependencies: phosphor_certificate_deps
)

executable(
    'phosphor-certificate-manager',
    'mainapp.cpp',
    dependencies: cert_manager_dep,
    install: true,
)

if not get_option('ca-cert-extension').disabled()
  subdir('bmc-vmi-ca')
endif

subdir('dist')

if not get_option('tests').disabled()
    subdir('test')
endif

