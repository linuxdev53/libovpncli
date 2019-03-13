# libovpncli library target
file (GLOB LIBOVPNCLI_SOURCES "*.c")
add_library (ovpncli_single STATIC ${LIBOVPNCLI_SOURCES})
target_include_directories (ovpncli_single PUBLIC ${CMAKE_BINARY_DIR}/libjsonc-helper-inst/include ${CMAKE_BINARY_DIR})

set (
	LIBOVPNCLI_LIBRARY
	"${CMAKE_BINARY_DIR}/src/libovpncli.a"
)

set_property (
	TARGET ovpncli_single PROPERTY C_STANDARD 99
)

set (
	LIBJSONC_HELPER_LIBRARY
	"${CMAKE_BINARY_DIR}/libjsonc-helper-inst/lib/libjsonc_helper.a"
)

add_custom_command (
	TARGET ovpncli_single
	POST_BUILD
	COMMAND mkdir -p ${CMAKE_BINARY_DIR}/src/tmp
)

if (MINGW)
	set (LIBOVPNCLI_OBJS *.obj)
else ()
	set (LIBOVPNCLI_OBJS *.o)
endif ()

add_custom_command (
	TARGET ovpncli_single
	POST_BUILD
	COMMAND ar -x ${CMAKE_BINARY_DIR}/src/libovpncli_single.a
	COMMAND ar -x ${LIBJSONC_HELPER_LIBRARY}
	COMMAND ar -rcs ${LIBOVPNCLI_LIBRARY} ${LIBOVPNCLI_OBJS}
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src/tmp
	COMMENT "Merging wih libjsonc_helper.a library"
)

install (FILES ${LIBOVPNCLI_LIBRARY} DESTINATION lib)
install (FILES libovpncli.h DESTINATION include)
