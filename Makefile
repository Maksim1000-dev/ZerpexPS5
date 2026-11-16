# ==========================================================================
# ZerpexPS5 — Makefile
# Сборка: GCC\bin\mingw32-make.exe  (запускать из корня D:\ZerpexPS5)
# Правила хозяина: ничего не скачивать; собранный EXE не запускать.
# ==========================================================================

GCC_DIR  := GCC
CXX      := $(GCC_DIR)/bin/g++.exe
IMGUI    := imgui-1.93.0/imgui-1.93.0

CXXFLAGS := -std=c++17 -O2 -m64 -Wall -DUNICODE -D_UNICODE \
            -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -DNTDDI_VERSION=0x06010000 \
            -I$(IMGUI) -I$(IMGUI)/backends -Isrc

# --- Лаунчер: оконное приложение (DX11 + ImGui) ---
LAUNCHER_LDFLAGS := -m64 -mwindows -static -static-libgcc -static-libstdc++
LAUNCHER_LIBS    := -ld3d11 -ldxgi -ld3dcompiler -ldwmapi -lwindowscodecs -limm32 -lole32 -luuid

LAUNCHER_SRCS := src/launcher/main.cpp \
                 src/core/log.cpp \
                 src/core/game.cpp \
                 src/core/texture.cpp \
                 $(IMGUI)/imgui.cpp \
                 $(IMGUI)/imgui_draw.cpp \
                 $(IMGUI)/imgui_tables.cpp \
                 $(IMGUI)/imgui_widgets.cpp \
                 $(IMGUI)/imgui_demo.cpp \
                 $(IMGUI)/backends/imgui_impl_dx11.cpp \
                 $(IMGUI)/backends/imgui_impl_win32.cpp

LAUNCHER_OUT := build/ZerpexLauncher.exe

# --- Ядро эмулятора: консольное приложение (фаза 5) ---
EMU_LDFLAGS := -m64 -static -static-libgcc -static-libstdc++
EMU_LIBS    := -lshell32

# Vulkan SDK (фаза 5): хедеры Khronos из локального SDK; DLL — системная,
# линковки нет (LoadLibrary в рантайме). Если SDK нет — gpu_vk.cpp
# честно собирается в режиме "слой отключён" (__has_include).
VK_INC := -Ivulkan/Include

EMU_SRCS := src/emu/main.cpp \
            src/emu/exec.cpp \
            src/emu/gpu.cpp \
            src/emu/gpu_vk.cpp \
            src/emu/pm4.cpp \
            src/emu/analyze.cpp \
            src/core/elf.cpp \
            src/core/mem.cpp \
            src/core/hle.cpp \
            src/core/dyn.cpp

EMU_OUT := build/ZerpexPS5.exe

all: $(LAUNCHER_OUT) $(EMU_OUT)

$(LAUNCHER_OUT): $(LAUNCHER_SRCS)
	@if not exist build mkdir build
	@echo === Сборка ZerpexLauncher.exe ===
	$(CXX) $(CXXFLAGS) $(VK_INC) $(LAUNCHER_SRCS) $(LAUNCHER_LDFLAGS) $(LAUNCHER_LIBS) -o $(LAUNCHER_OUT)
	@echo === Готово: $(LAUNCHER_OUT) ===

$(EMU_OUT): $(EMU_SRCS)
	@if not exist build mkdir build
	@echo === Сборка ZerpexPS5.exe ===
	$(CXX) $(CXXFLAGS) $(VK_INC) $(EMU_SRCS) $(EMU_LDFLAGS) $(EMU_LIBS) -o $(EMU_OUT)
	@echo === Готово: $(EMU_OUT) ===

clean:
	@if exist $(LAUNCHER_OUT) del $(LAUNCHER_OUT)
	@if exist $(EMU_OUT) del $(EMU_OUT)

.PHONY: all clean
