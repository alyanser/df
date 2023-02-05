cmake_minimum_required(VERSION 3.20)

project(dh)

add_executable(${PROJECT_NAME}
	dh.c
)

add_subdirectory(libsignal-protocol-c)

include_directories("libsignal-protocol-c/src")

target_link_libraries(${PROJECT_NAME}
	signal-protocol-c
	m
)
