#include "BMPlatform.h"
#include "Wrapper.h"

ClassHandle* createClass() {
    ClassHandle* handle = new ClassHandle;
    handle->obj = new CBootModeOpr();
    return handle;
}

void destroyClass(ClassHandle* handle) {
    delete static_cast<CBootModeOpr*>(handle->obj);
    delete handle;
}

BOOL call_Initialize(ClassHandle* handle) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->Initialize();
}

void call_Uninitialize(ClassHandle* handle) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    obj->Uninitialize();
}

int call_Read(ClassHandle* handle, UCHAR* m_RecvData, int max_len, int dwTimeout) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->Read(m_RecvData, max_len, dwTimeout);
}

int call_Write(ClassHandle* handle, UCHAR* lpData, int iDataSize) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->Write(lpData, iDataSize);
}

BOOL call_ConnectChannel(ClassHandle* handle, DWORD dwPort) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->ConnectChannel(dwPort);
}

BOOL call_DisconnectChannel(ClassHandle* handle) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->DisconnectChannel();
}

BOOL call_GetProperty(ClassHandle* handle, LONG lFlags, DWORD dwPropertyID, LPVOID pValue) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->GetProperty(lFlags, dwPropertyID, pValue);
}

BOOL call_SetProperty(ClassHandle* handle, LONG lFlags, DWORD dwPropertyID, LPCVOID pValue) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    return obj->SetProperty(lFlags, dwPropertyID, pValue);
}

void call_Clear(ClassHandle* handle) {
    CBootModeOpr* obj = static_cast<CBootModeOpr*>(handle->obj);
    obj->Clear();
}
