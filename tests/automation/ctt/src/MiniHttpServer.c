/******************************************************************
 *
 * Copyright 2016 Granite River Labs All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <MiniHttpServer.h>
#include <uv.h>

/*Static resource start*/
static uv_loop_t s_loopBasic;
static uv_async_t s_stopAsyncBasic;
static uv_thread_t s_serverThreadIDBasic;
static char* s_addrBasic;
static int s_portBasic;
static uv_loop_t s_loopSetup;
static uv_async_t s_stopAsyncSetup;
static uv_thread_t s_serverThreadIDSetup;
static char* s_addrSetup;
static int s_portSetup;
static uv_loop_t s_loopExtended;
static uv_async_t s_stopAsyncExtended;
static uv_thread_t s_serverThreadIDExtended;
static char* s_addrExtended;
static int s_portExtended;
static httpRequestCB s_onHttpRequestBasic;
static afterHttpRequestCB s_onAfterHttpRequestBasic;
static httpRequestCB s_onHttpRequestSetup;
static afterHttpRequestCB s_onAfterHttpRequestSetup;
static httpRequestCB s_onHttpRequestExtended;
static afterHttpRequestCB s_onAfterHttpRequestExtended;
/*Static resource end*/

typedef struct 
{
    uv_tcp_t* tcp;
    uv_buf_t buf;
} ReqData;

/*On Allocation of memory*/
static void onAlloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

/*Free Work request*/
static void freeWorkReq(uv_work_t* req, int status)
{
    free(req);
}

/*Create the response*/
static char* createResponse(char* body)
{
    //response template used for responding to TAF query
    char rspTemplate[] = "HTTP/1.1 200 OK\r\n" \
                       "Content-Type: text/xml; charset=iso-8859-1\r\n" \
                       "Content-Length: %d\r\n" \
                       "Connection: close\r\n" \
                       "\r\n" \
                       "%s";
    char* rsp = 0;

    if (body)
    {
        rsp = (char*)malloc(sizeof(char) * (strlen(body) + strlen(rspTemplate) + 16));
        sprintf(rsp, rspTemplate, strlen(body), body);
    }
    else
    {
        rsp = (char*)malloc(sizeof(char) * (strlen("") + strlen(rspTemplate) + 16));
        sprintf(rsp, rspTemplate, strlen(""), "");
    }

    return rsp;
}

/*Get string from the request buffer*/
static char* getMethod(uv_buf_t* req)
{
    char* end = strstr(req->base, " ");
    size_t size = end - req->base;
    char* ret = (char*)malloc(sizeof(char) * (size + 1));

    strncpy(ret, req->base, size);
    ret[size] = 0;

    return ret;
}


/*Get content length from the request buffer*/
static int getContentLength(uv_buf_t* req)
{
    int ret = -1;

    char* cl = strstr(req->base, "Content-Length:");
    char* rn = strstr(req->base, "\r\n\r\n");

    if (cl == 0) goto error;
    if (cl > rn) goto error;

    sscanf(cl, "Content-Length: %d", &ret);

    return ret;

error:
    return -1;
}

/*Calculate content length from the request buffer*/
static int calcContentLength(uv_buf_t* req)
{
    char* rn = strstr(req->base, "\r\n\r\n");
    int header_len = 0;

    if (rn == 0) goto error;

    header_len = rn - req->base + 4;

    return req->len - header_len;

error:
    return -1;
}

/*Get the URL from the request buffer*/
static char* getUrl(uv_buf_t* req)
{
    char* begin = strstr(req->base, " ") + 1;
    char* end = strstr(begin, " ");
    size_t size = end - begin;
    char* ret = (char*)malloc(sizeof(char) * (size + 1));

    strncpy(ret, begin, size);
    ret[size] = 0;

    return ret;
}

/*Get the body from the request buffer*/
static char* getBody(uv_buf_t* req)
{
    char* begin = 0;
    char* end = 0;
    char* ret = 0;
    size_t size = 0;

    begin = strstr(req->base, "\r\n\r\n");
    if (!begin) goto error;
    begin += 4;

    end = req->base + req->len;
    size = end - begin;

    if (size > 0)
    {
        ret = (char*)malloc(sizeof(char) * (size + 1));

        strncpy(ret, begin, size);
        ret[size] = 0;
    }

    return ret;

error:
    free(ret);

    return 0;
}

/*Delete the handle of request buffer*/
void deleteHandle(uv_handle_t* handle)
{
    free(handle);
}

/*Finish the request*/
void finishRequest(uv_write_t* req, int status)
{
    ReqData* reqData = (ReqData*)req->data;

    uv_close((uv_handle_t*) reqData->tcp, deleteHandle);

    free(reqData->buf.base);
    free(reqData);
    free(req);
}

/*Process Basic Request*/
static void processRequestBasic(uv_work_t* req)
{
    ReqData* reqData = (ReqData*) req->data;
    uv_write_t* writeReq = 0;
    char* rspBody = 0;
    char* rsp = 0;

    char* reqMethod = getMethod(&reqData->buf);
    char* reqUrl = getUrl(&reqData->buf);
    char* reqBody = getBody(&reqData->buf);

    if (s_onHttpRequestBasic)
    {
        rspBody = s_onHttpRequestBasic(reqMethod, reqUrl, reqBody);
    }

    rsp = createResponse(rspBody);

    free(reqData->buf.base);

    reqData->buf.base = rsp;
    reqData->buf.len = strlen(rsp);

    writeReq = (uv_write_t*)malloc(sizeof(uv_write_t));
    writeReq->data = reqData;

    uv_write(writeReq, (uv_stream_t*) reqData->tcp, &reqData->buf, 1, finishRequest);

    if (s_onAfterHttpRequestBasic)
    {
        s_onAfterHttpRequestBasic(rspBody);
    }

    free(reqBody);
    free(reqUrl);
    free(reqMethod);
}

/*Process Setup Request*/
static void processRequestSetup(uv_work_t* req)
{
    ReqData* reqData = (ReqData*) req->data;
    uv_write_t* writeReq = 0;
    char* rspBody = 0;
    char* rsp = 0;

    char* reqMethod = getMethod(&reqData->buf);
    char* reqUrl = getUrl(&reqData->buf);
    char* reqBody = getBody(&reqData->buf);

    if (s_onHttpRequestSetup)
    {
        rspBody = s_onHttpRequestSetup(reqMethod, reqUrl, reqBody);
    }

    rsp = createResponse(rspBody);

    free(reqData->buf.base);

    reqData->buf.base = rsp;
    reqData->buf.len = strlen(rsp);

    writeReq = (uv_write_t*)malloc(sizeof(uv_write_t));
    writeReq->data = reqData;

    uv_write(writeReq, (uv_stream_t*) reqData->tcp, &reqData->buf, 1, finishRequest);

    if (s_onAfterHttpRequestSetup)
    {
        s_onAfterHttpRequestSetup(rspBody);
    }

    free(reqBody);
    free(reqUrl);
    free(reqMethod);
}

/*Process Extended Request*/
static void processRequestExtended(uv_work_t* req)
{
    ReqData* reqData = (ReqData*) req->data;
    uv_write_t* writeReq = 0;
    char* rspBody = 0;
    char* rsp = 0;

    char* reqMethod = getMethod(&reqData->buf);
    char* reqUrl = getUrl(&reqData->buf);
    char* reqBody = getBody(&reqData->buf);

    if (s_onHttpRequestExtended)
    {
        rspBody = s_onHttpRequestExtended(reqMethod, reqUrl, reqBody);
    }

    rsp = createResponse(rspBody);

    free(reqData->buf.base);

    reqData->buf.base = rsp;
    reqData->buf.len = strlen(rsp);

    writeReq = (uv_write_t*)malloc(sizeof(uv_write_t));
    writeReq->data = reqData;

    uv_write(writeReq, (uv_stream_t*) reqData->tcp, &reqData->buf, 1, finishRequest);

    if (s_onAfterHttpRequestExtended)
    {
        s_onAfterHttpRequestExtended(rspBody);
    }

    free(reqBody);
    free(reqUrl);
    free(reqMethod);
}

/*Check if the request is complete*/
static int isRequestComplete(uv_buf_t* buf)
{
    int gcl = getContentLength(buf);
    int ccl = calcContentLength(buf);
    char* rnrn = strstr(buf->base, "\r\n\r\n");
    int ret = 0;

    if (rnrn)
    {
        if (gcl < 0)
        {
            ret = 1;
        }
        else if (gcl == ccl)
        {
            ret = 1;
        }
    }

    return ret;
}

/*Concatenate 2 strings*/
static char* concatString(char* str1, size_t len1, char* str2, size_t len2)
{
    char* ret = (char*)malloc(sizeof(char) * (len1 + len2 + 1));

    strncpy(ret, str1, len1);
    strncpy(ret + len1, str2, len2);
    ret[len1 + len2] = 0;

    return ret;
}

/*Read Basic Request*/
static void onReadBasic(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
    if (nread >= 0)
    {
        uv_work_t* req;
        ReqData* reqData;
        uv_buf_t* tcpBuf = 0;
        char* newBase = 0;
        int newLen = 0;

        if (tcp->data == 0)
        {
            tcp->data = malloc(sizeof(uv_buf_t));
            ((uv_buf_t*)tcp->data)->len = 0;
            ((uv_buf_t*)tcp->data)->base = 0;
        }

        tcpBuf = (uv_buf_t*)tcp->data;
        newLen = tcpBuf->len + nread;
        newBase = concatString(tcpBuf->base, tcpBuf->len, buf->base, nread);

        free(tcpBuf->base);
        tcpBuf->base = newBase;
        tcpBuf->len = newLen;

        if (isRequestComplete(tcpBuf))
        {
            req = (uv_work_t*) malloc(sizeof(uv_work_t));
            reqData = (ReqData*) malloc(sizeof(ReqData));

            reqData->tcp = (uv_tcp_t*)tcp;
            reqData->buf.base = tcpBuf->base;
            reqData->buf.len = tcpBuf->len;
            req->data = (void*)reqData;

            free(tcpBuf);
            tcp->data = 0;

            uv_queue_work(&s_loopBasic, req, processRequestBasic, freeWorkReq);
        }
    }
    else if (nread != UV__EOF)
    {
        if (tcp->data)
        {
            free(((uv_buf_t*)tcp->data)->base);
            free(tcp->data);
        }

        uv_close((uv_handle_t*) tcp, deleteHandle);
    }

    free(buf->base);
}

/*On New Basic Connection*/
static void onNewConnectionBasic(uv_stream_t *server, int status)
{
    uv_tcp_t *client;

    if (status == -1) {
        return;
    }

    client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    client->data = 0;
    uv_tcp_init(&s_loopBasic, client);

    if (uv_accept(server, (uv_stream_t*) client) == 0)
    {
        uv_read_start((uv_stream_t*) client, onAlloc, onReadBasic);
    }
    else
    {
        uv_close((uv_handle_t*) client, deleteHandle);
    }
}

/*Read Setup Request*/
static void onReadSetup(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
    if (nread >= 0)
    {
        uv_work_t* req;
        ReqData* reqData;
        uv_buf_t* tcpBuf = 0;
        char* newBase = 0;
        int newLen = 0;

        if (tcp->data == 0)
        {
            tcp->data = malloc(sizeof(uv_buf_t));
            ((uv_buf_t*)tcp->data)->len = 0;
            ((uv_buf_t*)tcp->data)->base = 0;
        }

        tcpBuf = (uv_buf_t*)tcp->data;
        newLen = tcpBuf->len + nread;
        newBase = concatString(tcpBuf->base, tcpBuf->len, buf->base, nread);

        free(tcpBuf->base);
        tcpBuf->base = newBase;
        tcpBuf->len = newLen;

        if (isRequestComplete(tcpBuf))
        {
            req = (uv_work_t*) malloc(sizeof(uv_work_t));
            reqData = (ReqData*) malloc(sizeof(ReqData));

            reqData->tcp = (uv_tcp_t*)tcp;
            reqData->buf.base = tcpBuf->base;
            reqData->buf.len = tcpBuf->len;
            req->data = (void*)reqData;

            free(tcpBuf);
            tcp->data = 0;

            uv_queue_work(&s_loopSetup, req, processRequestSetup, freeWorkReq);
        }
    }
    else if (nread != UV__EOF)
    {
        if (tcp->data)
        {
            free(((uv_buf_t*)tcp->data)->base);
            free(tcp->data);
        }

        uv_close((uv_handle_t*) tcp, deleteHandle);
    }

    free(buf->base);
}

/*On New Setup Connection*/
static void onNewConnectionSetup(uv_stream_t *server, int status)
{
    uv_tcp_t *client;

    if (status == -1) {
        return;
    }

    client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    client->data = 0;
    uv_tcp_init(&s_loopSetup, client);

    if (uv_accept(server, (uv_stream_t*) client) == 0)
    {
        uv_read_start((uv_stream_t*) client, onAlloc, onReadSetup);
    }
    else
    {
        uv_close((uv_handle_t*) client, deleteHandle);
    }
}


/*Read Extended Request*/
static void onReadExtended(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
    if (nread >= 0)
    {
        uv_work_t* req;
        ReqData* reqData;
        uv_buf_t* tcpBuf = 0;
        char* newBase = 0;
        int newLen = 0;

        if (tcp->data == 0)
        {
            tcp->data = malloc(sizeof(uv_buf_t));
            ((uv_buf_t*)tcp->data)->len = 0;
            ((uv_buf_t*)tcp->data)->base = 0;
        }

        tcpBuf = (uv_buf_t*)tcp->data;
        newLen = tcpBuf->len + nread;
        newBase = concatString(tcpBuf->base, tcpBuf->len, buf->base, nread);

        free(tcpBuf->base);
        tcpBuf->base = newBase;
        tcpBuf->len = newLen;

        if (isRequestComplete(tcpBuf))
        {
            req = (uv_work_t*) malloc(sizeof(uv_work_t));
            reqData = (ReqData*) malloc(sizeof(ReqData));

            reqData->tcp = (uv_tcp_t*)tcp;
            reqData->buf.base = tcpBuf->base;
            reqData->buf.len = tcpBuf->len;
            req->data = (void*)reqData;

            free(tcpBuf);
            tcp->data = 0;

            uv_queue_work(&s_loopExtended, req, processRequestExtended, freeWorkReq);
        }
    }
    else if (nread != UV__EOF)
    {
        if (tcp->data)
        {
            free(((uv_buf_t*)tcp->data)->base);
            free(tcp->data);
        }

        uv_close((uv_handle_t*) tcp, deleteHandle);
    }

    free(buf->base);
}

/*On New Extended Connection*/
static void onNewConnectionExtended(uv_stream_t *server, int status)
{
    uv_tcp_t *client;

    if (status == -1) {
        return;
    }

    client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    client->data = 0;
    uv_tcp_init(&s_loopExtended, client);

    if (uv_accept(server, (uv_stream_t*) client) == 0)
    {
        uv_read_start((uv_stream_t*) client, onAlloc, onReadExtended);
    }
    else
    {
        uv_close((uv_handle_t*) client, deleteHandle);
    }
}

/*Stop Basic Http Server*/
static void stopMiniHttpServerAsyncBasic(uv_async_t* handle)
{
    uv_stop(&s_loopBasic);
}

/*Stop Setup Http Server*/
static void stopMiniHttpServerAsyncSetup(uv_async_t* handle)
{
    uv_stop(&s_loopSetup);
}

/*Stop Extended Http Server*/
static void stopMiniHttpServerAsyncExtended(uv_async_t* handle)
{
    uv_stop(&s_loopExtended);
}

/*Start Basic Http Server Thread*/
static void miniHttpServerThreadBasic(void *arg)
{
    uv_tcp_t server;
    struct sockaddr_in bindAddr;

    uv_loop_init(&s_loopBasic);
    uv_tcp_init(&s_loopBasic, &server);
    uv_async_init(&s_loopBasic, &s_stopAsyncBasic, stopMiniHttpServerAsyncBasic);

    uv_ip4_addr(s_addrBasic, s_portBasic, &bindAddr);
    uv_tcp_bind(&server, (const struct sockaddr*)&bindAddr, 0);

    uv_listen((uv_stream_t*) &server, 128, onNewConnectionBasic);
    uv_run(&s_loopBasic, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&server, 0);
}

/*Stop Basic Http Server*/
void stopMiniHttpServerBasic()
{
    uv_async_send(&s_stopAsyncBasic);
    uv_thread_join(&s_serverThreadIDBasic);

    free(s_addrBasic);
    s_addrBasic = 0;
    s_portBasic = 0;
    s_onHttpRequestBasic = 0;
}

/*Start Basic Http Server*/
void startMiniHttpServerBasic(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest)
{
    int addrLen = strlen(addr);
    s_addrBasic = (char*) malloc(sizeof(char) * (addrLen + 1));
    strcpy(s_addrBasic, addr);
    s_addrBasic[addrLen] = 0;
    s_portBasic = port;
    s_onHttpRequestBasic = onHttpRequest;
    s_onAfterHttpRequestBasic = onAfterHttpRequest;

    uv_thread_create(&s_serverThreadIDBasic, miniHttpServerThreadBasic, 0);
}

/*Start Setup Http Server Thread*/
static void miniHttpServerThreadSetup(void *arg)
{
    uv_tcp_t server;
    struct sockaddr_in bindAddr;

    uv_loop_init(&s_loopSetup);
    uv_tcp_init(&s_loopSetup, &server);
    uv_async_init(&s_loopSetup, &s_stopAsyncSetup, stopMiniHttpServerAsyncSetup);

    uv_ip4_addr(s_addrSetup, s_portSetup, &bindAddr);
    uv_tcp_bind(&server, (const struct sockaddr*)&bindAddr, 0);

    uv_listen((uv_stream_t*) &server, 128, onNewConnectionSetup);
    uv_run(&s_loopSetup, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&server, 0);
}

/*Stop Setup Http Server Thread*/
void stopMiniHttpServerSetup()
{
    uv_async_send(&s_stopAsyncSetup);
    uv_thread_join(&s_serverThreadIDSetup);

    free(s_addrSetup);
    s_addrSetup = 0;
    s_portSetup = 0;
    s_onHttpRequestSetup = 0;
}

/*Start Setup Http Server*/
void startMiniHttpServerSetup(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest)
{
    int addrLen = strlen(addr);
    s_addrSetup = (char*) malloc(sizeof(char) * (addrLen + 1));
    strcpy(s_addrSetup, addr);
    s_addrSetup[addrLen] = 0;
    s_portSetup = port;
    s_onHttpRequestSetup = onHttpRequest;
    s_onAfterHttpRequestSetup = onAfterHttpRequest;

    uv_thread_create(&s_serverThreadIDSetup, miniHttpServerThreadSetup, 0);
}


/*Start Extended Http Server Thread*/
static void miniHttpServerThreadExtended(void *arg)
{
    uv_tcp_t server;
    struct sockaddr_in bindAddr;

    uv_loop_init(&s_loopExtended);
    uv_tcp_init(&s_loopExtended, &server);
    uv_async_init(&s_loopExtended, &s_stopAsyncExtended, stopMiniHttpServerAsyncExtended);

    uv_ip4_addr(s_addrExtended, s_portExtended, &bindAddr);
    uv_tcp_bind(&server, (const struct sockaddr*)&bindAddr, 0);

    uv_listen((uv_stream_t*) &server, 128, onNewConnectionExtended);
    uv_run(&s_loopExtended, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&server, 0);
}

/*Stop Extended Http Server*/
void stopMiniHttpServerExtended()
{
    uv_async_send(&s_stopAsyncExtended);
    uv_thread_join(&s_serverThreadIDExtended);

    free(s_addrExtended);
    s_addrExtended = 0;
    s_portExtended = 0;
    s_onHttpRequestExtended = 0;
}

/*Start Extended Http Server*/
void startMiniHttpServerExtended(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest)
{
    int addrLen = strlen(addr);
    s_addrExtended = (char*) malloc(sizeof(char) * (addrLen + 1));
    strcpy(s_addrExtended, addr);
    s_addrExtended[addrLen] = 0;
    s_portExtended = port;
    s_onHttpRequestExtended = onHttpRequest;
    s_onAfterHttpRequestExtended = onAfterHttpRequest;

    uv_thread_create(&s_serverThreadIDExtended, miniHttpServerThreadExtended, 0);
}
