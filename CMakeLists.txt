
# libovpncli project settings
cmake_minimum_required (VERSION 2.8.11)
project (libovpncli)
set (CMAKE_BUILD_TYPE Release)

# set libovpncli version
set (LIBOVPNCLI_VERSION "0.9.0")

execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set (GIT_COMMIT_HASH ${GIT_COMMIT_HASH})

# set configuration file
configure_file (
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
)

OPTION(LIBOVC_DEBUG
	"Build libovpncli using debugging code"
	OFF)
IF(LIBOVC_DEBUG)
	MESSAGE("Adding DEBUG flag...")
	ADD_DEFINITIONS(-DLIBOVC_DEBUG)
	SET(CMAKE_BUILD_TYPE Debug)
	MESSAGE("Build type is " ${CMAKE_BUILD_TYPE})
ENDIF(LIBOVC_DEBUG)

# check functions
include (${CMAKE_ROOT}/Modules/CheckFunctionExists.cmake)

CHECK_FUNCTION_EXISTS(strlcpy HAVE_STRLCPY)
CHECK_FUNCTION_EXISTS(strlcat HAVE_STRLCAT)

# add libjsonc-helper dependency
include (ExternalProject)

ExternalProject_Add (
	libjsonc-helper
	GIT_REPOSITORY https://github.com/linuxdev53/jsonc-helper
	GIT_TAG ""
	UPDATE_COMMAND ""
	PATCH_COMMAND ""
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/libjsonc-helper-inst
)

# add subdirectory
add_subdirectory (src)

enable_testing ()
add_subdirectory (tests)
