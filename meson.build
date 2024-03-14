project('hashmap', 'c',
  version : '1.0',
  default_options : ['warning_level=3','c_std=c17','c_args=-Werror -g','b_sanitize=address','prefer_static=true'])

#we don't *need* this
#pkg = import('pkgconfig')

hmdeps = [dependency('openssl')]#,dependency('crypto')]
install_headers('include/hashmap.h',preserve_path:true)
#l=['-Wl,--rpath=${libdir}']
#l=['-Wl,--rpath='+get_option('libdir')]
incdir = include_directories('include')
hm_a=static_library('hashmap',
           'hashmap.c',
           dependencies : hmdeps,
           install : true,
           include_directories : incdir)
hm_s=shared_library('hashmap',
           'hashmap.c',
           dependencies : hmdeps,
           install : true,
           include_directories : incdir)
#pkg.generate(hm,variables:['libs=${libdir}/libhashmap.so'])#,libraries : l)

hm_lib=declare_dependency(link_with:hm_a,include_directories:incdir)
hm_lib_shared=declare_dependency(link_with:hm_s,include_directories:incdir)


