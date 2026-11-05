# Build file for the harbour gauge daemon.
project('saltmere-gauge', 'c', version : '1.4.0', license : 'CC0-1.0')

glib = dependency('glib-2.0')
m = dependency('m')

subdir('docs')

exe = executable('gauged', 'gauged.c', dependencies : [glib, m])
lib = static_library('tides', 'tides.c')
test('tides', executable('test-tides', 'test.c', link_with : lib))
