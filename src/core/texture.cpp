// ============================================================================
// ZerpexPS5 — ядро: текстуры обложек (реализация, WIC)
// ============================================================================
#include "texture.h"

#include <map>
#include <vector>
#include <wincodec.h>

namespace zrx {

namespace {
std::map<std::wstring, Texture> g_cache;
}

Texture* GetTexture(ID3D11Device* dev, const std::wstring& path) {
    if (!dev || path.empty())
        return nullptr;

    auto it = g_cache.find(path);
    if (it != g_cache.end())
        return it->second.srv ? &it->second : nullptr;

    Texture t;
    IWICImagingFactory* fac = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_PPV_ARGS(&fac))) && fac) {
        IWICBitmapDecoder* dec = nullptr;
        if (SUCCEEDED(fac->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                       WICDecodeMetadataCacheOnDemand, &dec)) && dec) {
            IWICBitmapFrameDecode* frame = nullptr;
            if (SUCCEEDED(dec->GetFrame(0, &frame)) && frame) {
                UINT w = 0, h = 0;
                frame->GetSize(&w, &h);
                t.w = (int)w;
                t.h = (int)h;

                IWICFormatConverter* conv = nullptr;
                if (SUCCEEDED(fac->CreateFormatConverter(&conv)) && conv) {
                    if (SUCCEEDED(conv->Initialize(frame, GUID_WICPixelFormat32bppBGRA,
                                                   WICBitmapDitherTypeNone, nullptr, 0.0,
                                                   WICBitmapPaletteTypeCustom))) {
                        std::vector<unsigned char> px((size_t)w * h * 4);
                        if (w && h &&
                            SUCCEEDED(conv->CopyPixels(nullptr, w * 4, px.size(), px.data()))) {
                            D3D11_TEXTURE2D_DESC td = {};
                            td.Width  = w;
                            td.Height = h;
                            td.MipLevels = 1;
                            td.ArraySize = 1;
                            td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
                            td.SampleDesc.Count = 1;
                            td.Usage = D3D11_USAGE_IMMUTABLE;
                            td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
                            D3D11_SUBRESOURCE_DATA sd = { px.data(), w * 4, 0 };
                            ID3D11Texture2D* tex = nullptr;
                            if (SUCCEEDED(dev->CreateTexture2D(&td, &sd, &tex)) && tex) {
                                if (FAILED(dev->CreateShaderResourceView(tex, nullptr, &t.srv)))
                                    t.srv = nullptr;
                                tex->Release();
                            }
                        }
                    }
                    conv->Release();
                }
                frame->Release();
            }
            dec->Release();
        }
        fac->Release();
    }

    g_cache[path] = t;
    auto rit = g_cache.find(path);
    return rit->second.srv ? &rit->second : nullptr;
}

void ReleaseTextures() {
    for (auto& kv : g_cache) {
        if (kv.second.srv)
            kv.second.srv->Release();
    }
    g_cache.clear();
}

} // namespace zrx
