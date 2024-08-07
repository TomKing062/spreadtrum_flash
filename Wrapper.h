#ifndef WRAPPER_H
#define WRAPPER_H
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        void* obj;
    } ClassHandle;

    ClassHandle* createClass();
    void destroyClass(ClassHandle* handle);
    BOOL call_Initialize(ClassHandle* handle);
    void call_Uninitialize(ClassHandle* handle);
    int call_Read(ClassHandle* handle, UCHAR* m_RecvData, int max_len, int dwTimeout);
    int call_Write(ClassHandle* handle, UCHAR* lpData, int iDataSize);
    BOOL call_ConnectChannel(ClassHandle* handle, DWORD dwPort);
    BOOL call_DisconnectChannel(ClassHandle* handle);
    BOOL call_GetProperty(ClassHandle* handle, LONG lFlags, DWORD dwPropertyID, LPVOID pValue);
    BOOL call_SetProperty(ClassHandle* handle, LONG lFlags, DWORD dwPropertyID, LPCVOID pValue);
    void call_Clear(ClassHandle* handle);

#ifdef __cplusplus
}
#endif

#endif
