project('libmc7', 'c',
  version: 'v0.4.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ])

libmc7_deps = []
libmc7_src = ['src' / 'simatic.c']
libmc7_incs = ['include']

if get_option('build_shared_libs')
  rizin = find_program('rizin', required: false)
  rz_analysis_dep = dependency('rz_analysis')
  rz_asm_dep = dependency('rz_asm')
  rz_bin_dep = dependency('rz_bin')

  analysis_plugdir = rz_analysis_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_analysis_PLUGINDIR')
  asm_plugdir = rz_asm_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_asm_PLUGINDIR')
  bin_plugdir = rz_bin_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_bin_PLUGINDIR')

  libmc7_analysis_src = libmc7_src + ['src' / 'plugin_analysis.c']
  libmc7_analysis_deps = libmc7_deps + [rz_analysis_dep]
  shared_library('mc7_analysis', libmc7_analysis_src,
    dependencies: libmc7_analysis_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: analysis_plugdir
  )

  libmc7_asm_src = libmc7_src + ['src' / 'plugin_asm.c']
  libmc7_asm_deps = libmc7_deps + [rz_asm_dep]
  shared_library('mc7_asm', libmc7_asm_src,
    dependencies: libmc7_asm_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: asm_plugdir
  )

  # This plugin is not in a working state, plus is difficult to find any example.
  # libmc7_bin_src = libmc7_src + ['src' / 'plugin_bin.c']
  # libmc7_bin_deps = libmc7_deps + [rz_bin_dep]
  # shared_library('mc7_bin', libmc7_bin_src,
  #   dependencies: libmc7_bin_deps,
  #   include_directories: include_directories(libmc7_incs),
  #   implicit_include_directories: false,
  #   install: true,
  #   install_dir: bin_plugdir
  # )
endif

exe = executable('test_simatic', ['unit' / 'test_simatic.c'] + libmc7_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test('test_simatic', exe)