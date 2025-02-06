project('libmc7', 'c',
  version: 'v0.4.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ])


libmc7_deps = []
if get_option('build_shared_libs')
  rizin = find_program('rizin', required: false)
  rz_core_dep = dependency('rz_core')
  libmc7_deps += rz_core_dep
  libmc7_deps += dependency('rz_util')
  libmc7_deps += dependency('rz_cons')
  libmc7_deps += dependency('rz_config')
  libmc7_deps += dependency('rz_io')
  
  rizin_plugdir = ''
  if rizin_plugdir == ''
    rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
    plugin_libmc7_dir = join_paths(get_option('prefix'), rizin_plugdir, 'libmc7')
  else
    plugin_libmc7_dir = join_paths(rizin_plugdir, 'libmc7')
  endif
  message(' - ',plugin_libmc7_dir )

  libmc7_incs = ['.', 'src','include']
  libmc7_c_args = []
  libmc7_asm_src = [
    'src' / 'simatic.c',
    'src' / 'plugin_asm.c',	
  ]
  shared_library('libmc7_asm', libmc7_asm_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir
  )
  libmc7_analysis_src = [
    'src' / 'simatic.c',
    'src' / 'plugin_analysis.c',	
  ]
  shared_library('libmc7_analysis', libmc7_analysis_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir
  )
  libmc7_bin_src = [
    'src' / 'simatic.c',
    'src' / 'plugin_bin.c',	
  ]
  shared_library('libmc7_bin', libmc7_bin_src,
    c_args : libmc7_c_args,
    dependencies: libmc7_deps,
    include_directories: include_directories(libmc7_incs),
    implicit_include_directories: false,
    install: true,
    install_dir: rizin_plugdir
  )
endif

libmc7_src = ['src' / 'simatic.c']
exe = executable('test_simatic', ['unit' / 'test_simatic.c'] + libmc7_src,
  c_args: [],
  include_directories: include_directories(libmc7_incs),
  dependencies: [],
  install: false,
  implicit_include_directories: false)

test('test_simatic', exe)