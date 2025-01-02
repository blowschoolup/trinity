cmake_minimum_required(VERSION 3.22)
project(SHVE_CPLUS)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-O3)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer")
find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
if(OPENSSL_FOUND)
    message(STATUS "OPENSSL_VERSION = ${OPENSSL_VERSION}")
endif(OPENSSL_FOUND)

find_package(OpenMP REQUIRED)

aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR}/cpp/engine enginefile)
aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR}/cpp/param paramfile)
aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR}/cpp/QuotientFilter QuotientFilterfile)
aux_source_directory (${CMAKE_CURRENT_SOURCE_DIR}/cpp/util utilfile)

add_executable(SHVE_CPLUS main.cpp ${enginefile} ${paramfile} ${QuotientFilterfile} ${utilfile})
target_include_directories(SHVE_CPLUS PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
#target_link_libraries(SHVE_CPLUS ${OPENSSL_LIBRARIES} ntl gmp m pthread)
target_link_libraries(SHVE_CPLUS libssl.a libcrypto.a libntl.a libgmp.a m OpenMP::OpenMP_CXX pthread dl)