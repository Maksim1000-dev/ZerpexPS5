// ============================================================================
// ZerpexPS5 — ядро: текстуры обложек
// Загрузка PNG через Windows Imaging Component (WIC) → D3D11 SRV.
// Никаких внешних зависимостей: WIC есть в любой Windows.
// ============================================================================
#pragma once

#include <d3d11.h>
#include <string>

namespace zrx {

struct Texture {
    ID3D11ShaderResourceView* srv = nullptr;
    int w = 0, h = 0;
};

// Загружает картинку по пути и кеширует. Возвращает nullptr при неудаче
// (неудача тоже кешируется — чтобы не грузить битый файл каждый кадр).
Texture* GetTexture(ID3D11Device* dev, const std::wstring& path);

// Освободить все текстуры (вызывать ДО освобождения устройства)
void ReleaseTextures();

} // namespace zrx
