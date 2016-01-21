

#include <stdlib.h>
#include <string.h>

#include "stunclient.h"

#include "stun_intern.h"

#include "stuntrace.h"
void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData);

static bool
isDstUnreachable(int32_t   ICMPtype,
                 u_int16_t addrFamily)
{
  if ( ( (ICMPtype == 3) && (addrFamily == AF_INET) )  ||
       ( (ICMPtype == 1) && (addrFamily == AF_INET6) ) )
  {
    return true;
  }
  return false;
}

static bool
isTimeExceeded(int32_t   ICMPtype,
               u_int16_t addrFamily)
{
  if ( ( (ICMPtype == 11) && (addrFamily == AF_INET) )  ||
       ( (ICMPtype == 3) && (addrFamily == AF_INET6) ) )
  {
    return true;
  }
  return false;
}


void
sendCallback(struct hiutResult* result,
             struct sockaddr*   addr,
             uint32_t           hop,
             uint32_t           rtt,
             uint32_t           retrans,
             bool               traceEnd,
             bool               done)
{

  StunTraceCallBackData_T data;
  data.nodeAddr    = addr;
  data.hop         = hop;
  data.rtt         = rtt;
  data.retransmits = retrans;
  data.trace_num   = result->num_traces;
  data.traceEnd    = traceEnd;
  data.done        = done;

  result->traceCb(result->userCtx, &data);
}

void
resartIfNotDone(struct hiutResult* result)
{
  bool done = result->num_traces < result->max_recuring ? false : true;
  if (!done)
  {
    result->num_traces++;
    result->currentTTL = 1;
    for (int i = 0; i < MAX_TTL; i++)
    {
      result->pathElement[i].gotAnswer = false;
    }
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->currStunMsgId,
                               result->sockfd,
                               result->sendFunc,
                               StunStatusCallBack,
                               NULL );

  }
}



int
numConcecutiveInactiveNodes(const struct hiutResult* result)
{
  int max = 0;
  int num = 0;

  for (int i = 0; i < MAX_TTL; i++)
  {
    if (result->pathElement[i].inactive)
    {
      num++;
    }
    else
    {
      if (num > max)
      {
        max = num;
      }
      num = 0;
    }
  }
  return max;
}

void
handleStunNoAnswer(struct hiutResult* result)
{
  result->pathElement[result->currentTTL].inactive = true;
  /* Hov many no answer in a row? */
  if (numConcecutiveInactiveNodes(result) >= MAX_CONCECUTIVE_INACTIVE &&
     !result->remoteAlive)
  {
    bool done = result->num_traces < result->max_recuring ? false : true;
    result->path_max_ttl = result->currentTTL - MAX_CONCECUTIVE_INACTIVE;
    sendCallback(result,
                 NULL,
                 result->currentTTL,
                 0,
                 0,
                 true,
                 done);
    resartIfNotDone(result);
    return;
  }

  sendCallback(result,
               NULL,
               result->currentTTL,
               0,
               0,
               false,
               false);

  if ( result->currentTTL < result->user_max_ttl )
  {
    while (result->pathElement[result->currentTTL].inactive &&
           result->currentTTL < result->path_max_ttl)
    {
      result->currentTTL++;
    }
    stunlib_createId(&result->currStunMsgId,
                     rand(), result->currentTTL);
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->currStunMsgId,
                               result->sockfd,
                               result->sendFunc,
                               StunStatusCallBack,
                               NULL );
  }
  else
  {
    /* TODO: Callabck here */
    /*
     *  stopAndExit(result);
     */
  }
}

void
handleStunRespIcmp(struct hiutResult* result,
                   int                ICMPtype,
                   int                ttl,
                   struct sockaddr*   srcAddr,
                   int                rtt,
                   int                retransmits)
{
  STUN_CLIENT_DATA* clientData = (STUN_CLIENT_DATA*) result->stunCtx;

  if ( (ttl == MAX_TTL) &&
       isDstUnreachable(ICMPtype, srcAddr->sa_family) )
  {
    /* Part of far end alive test */
    result->remoteAlive = true;
    result->currentTTL  = 1;

    stunlib_createId(&result->currStunMsgId,
                     rand(), result->currentTTL);

    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->currStunMsgId,
                               result->sockfd,
                               result->sendFunc,
                               StunStatusCallBack,
                               NULL );
    return;
  }
  if ( isTimeExceeded(ICMPtype, srcAddr->sa_family) )
  {
    if (result->currentTTL < result->user_max_ttl)
    {
      result->currentTTL++;
      while (result->pathElement[result->currentTTL].inactive &&
             result->currentTTL < result->path_max_ttl)
      {
        result->currentTTL++;
      }
      if (result->currentTTL <= result->path_max_ttl)
      {
        sendCallback(result,
                     srcAddr,
                     ttl,
                     rtt,
                     retransmits,
                     false,
                     false);

        stunlib_createId(&result->currStunMsgId,
                         rand(), result->currentTTL);

        StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                                   result,
                                   (struct sockaddr*)&result->remoteAddr,
                                   (struct sockaddr*)&result->localAddr,
                                   false,
                                   result->username,
                                   result->password,
                                   result->currentTTL,
                                   result->currStunMsgId,
                                   result->sockfd,
                                   result->sendFunc,
                                   StunStatusCallBack,
                                   NULL );
      }
      else
      {
        bool done = result->num_traces < result->max_recuring ? false : true;
        sendCallback(result,
                     srcAddr,
                     ttl,
                     rtt,
                     retransmits,
                     true,
                     done);
        resartIfNotDone(result);
      }
    }
    else
    {
      /* do nothing */
    }
  }
  else if ( isDstUnreachable(ICMPtype,srcAddr->sa_family) )
  {
    bool done = result->num_traces < result->max_recuring ? false : true;

    if (result->path_max_ttl >= ttl)
    {
      result->path_max_ttl = ttl;

      sendCallback(result,
                   srcAddr,
                   ttl,
                   rtt,
                   retransmits,
                   true,
                   done);

      resartIfNotDone(result);
    }
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Trace,
              "<STUNTRACE> handleStunRespIcmp: Ignoring ICMP type: %i\n ",
              ICMPtype);

  }
}

void
handleStunRespSucsessfull(struct hiutResult* result,
                          int                ttl,
                          struct sockaddr*   srcAddr,
                          struct sockaddr*   rflxAddr,
                          int                rtt,
                          int                retransmits)
{
  /* char addr[SOCKADDR_MAX_STRLEN]; */
  (void) rflxAddr;
  if (ttl == MAX_TTL)
  {
    /* Part of far end alive test */
    result->remoteAlive = true;
    result->currentTTL  = 1;

    stunlib_createId(&result->currStunMsgId,
                     rand(), result->currentTTL);

    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->currStunMsgId,
                               result->sockfd,
                               result->sendFunc,
                               StunStatusCallBack,
                               NULL );
      return;
  }

  bool done = result->num_traces < result->max_recuring ? false : true;
  if ( sockaddr_sameAddr( (struct sockaddr*)&result->remoteAddr,srcAddr ) )
  {
    if (result->path_max_ttl >= ttl)
    {
      result->path_max_ttl = ttl;
      sendCallback(result,
                   srcAddr,
                   ttl,
                   rtt,
                   retransmits,
                   true,
                   done);

      resartIfNotDone(result);
      return;
    }
  }
}



void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData)
{
  struct hiutResult* result = (struct hiutResult*)userCtx;

  if (result->pathElement[stunCbData->ttl].gotAnswer)
  {
    printf("Got this one already! Ignoring (%i)\n", stunCbData->ttl);
    return;
  }
  result->pathElement[stunCbData->ttl].gotAnswer = true;

  switch (stunCbData->stunResult)
  {
  case StunResult_BindOk:
    handleStunRespSucsessfull( (struct hiutResult*)userCtx,
                               stunCbData->ttl,
                               (struct sockaddr*)&stunCbData->srcAddr,
                               (struct sockaddr*)&stunCbData->rflxAddr,
                               stunCbData->rtt,
                               stunCbData->retransmits );
    break;
  case StunResult_ICMPResp:
    handleStunRespIcmp( (struct hiutResult*)userCtx,
                        stunCbData->ICMPtype,
                        stunCbData->ttl,
                        (struct sockaddr*)&stunCbData->srcAddr,
                        stunCbData->rtt,
                        stunCbData->retransmits );
    break;
  case StunResult_BindFailNoAnswer:
    handleStunNoAnswer( (struct hiutResult*)userCtx );
    break;
  default:
    return;
  }
}

int
StunTrace_startTrace(STUN_CLIENT_DATA*      clientData,
                     void*                  userCtx,
                     const struct sockaddr* toAddr,
                     const struct sockaddr* fromAddr,
                     uint32_t               sockhandle,
                     const char*            ufrag,
                     const char*            password,
                     uint32_t               numTraces,
                     STUN_TRACECB           traceCbFunc,
                     STUN_SENDFUNC          sendFunc)
{
  struct hiutResult* result;
  uint32_t           len;

  result = &clientData->traceResult;

  result->currentTTL = MAX_TTL;
  result->userCtx    = userCtx;
  stunlib_createId(&result->currStunMsgId, rand(), 1);
  result->stunCtx = clientData;
  /* Fill inn the hiut struct so we get something back in the CB */
  /* TODO: Fix the struct so we do not store information twice!! */
  sockaddr_copy( (struct sockaddr*)&clientData->traceResult.localAddr,
                 fromAddr );
  sockaddr_copy( (struct sockaddr*)&clientData->traceResult.remoteAddr,
                 toAddr );

  result->user_max_ttl         = 40;
  result->user_start_ttl       = 1;
  result->wait_ms              = 0;
  result->max_recuring         = numTraces;
  result->user_paralell_traces = 0;
  result->path_max_ttl         = 255;
  result->num_traces           = 1;
  result->traceCb              = traceCbFunc;
  result->sendFunc             = sendFunc;
  result->sockfd               = sockhandle;

  strncpy(result->username, ufrag,    sizeof(result->username) - 1);
  strncpy(result->password, password, sizeof(result->password) - 1);

  len = StunClient_startSTUNTrace(result->stunCtx,
                                  result,
                                  toAddr,
                                  fromAddr,
                                  false,
                                  result->username,
                                  result->password,
                                  result->currentTTL,
                                  result->currStunMsgId,
                                  result->sockfd,
                                  result->sendFunc,
                                  StunStatusCallBack,
                                  NULL);
  result->stunLen = len;

  return len;

}
