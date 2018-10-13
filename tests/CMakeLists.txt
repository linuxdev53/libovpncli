set (
	LIBOVPNCLI
	${CMAKE_BINARY_DIR}/src/libovpncli.a
)

add_executable (ovpn_cli_test ovpn_cli_test.c)
include_directories (${CMAKE_SOURCE_DIR}/src ${CMAKE_BINRARY_DIR}/tests)
target_link_libraries (ovpn_cli_test ${LIBOVPNCLI} -lws2_32)

add_test (NAME ovpn_cli_test COMMAND ovpn_cli_test ${CMAKE_SOURCE_DIR}/tests/test.cfg)
