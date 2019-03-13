set (
	LIBOVPNCLI
	${CMAKE_BINARY_DIR}/src/libovpncli.a
)

add_executable (ovpn_cli_test ovpn_cli_test.c)
include_directories (${CMAKE_SOURCE_DIR}/src ${CMAKE_BINRARY_DIR}/tests)

if (MINGW)
target_link_libraries (ovpn_cli_test ${LIBOVPNCLI} -lpthread -lws2_32)
else ()
target_link_libraries (ovpn_cli_test ${LIBOVPNCLI} -lpthread)
endif ()


add_test (NAME ovpn_cli_test COMMAND ovpn_cli_test ${CMAKE_SOURCE_DIR}/tests/test.cfg)
