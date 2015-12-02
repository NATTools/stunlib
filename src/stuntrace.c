

#include <stdlib.h>
#include <string.h>

#include "stunclient.h"

#include "stun_intern.h"

#include "stuntrace.h"
void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData);



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
                               result->ttlInfo[result->currentTTL].stunMsgId,
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
  if (numConcecutiveInactiveNodes(result) >= MAX_CONCECUTIVE_INACTIVE)
  {
    bool done = result->num_traces < result->max_recuring ? false : true;

    result->path_max_ttl = result->currentTTL-MAX_CONCECUTIVE_INACTIVE;

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

  if ( (result->currentTTL < result->user_max_ttl) &&
       (result->currentTTL < result->path_max_ttl) )
  {
    //
    //result->pathElement[result->currentTTL].inactive = true;

    while (result->pathElement[result->currentTTL].inactive &&
           result->currentTTL < result->path_max_ttl)
    {
      result->currentTTL++;
    }

    stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                     rand(), result->currentTTL);
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->ttlInfo[result->currentTTL].stunMsgId,
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
  if (ttl >= result->user_max_ttl)
  {
    /*
     *  stopAndExit(result);
     */
    /* Do callback to user here.. */
  }

  /* printf("Type: %i\n", ICMPtype); */
  if ( ( (ICMPtype == 11) && (srcAddr->sa_family == AF_INET) ) ||
       ( (ICMPtype == 3) && (srcAddr->sa_family == AF_INET6) ) )
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

        stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                         rand(), result->currentTTL);

        StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                                   result,
                                   (struct sockaddr*)&result->remoteAddr,
                                   (struct sockaddr*)&result->localAddr,
                                   false,
                                   result->username,
                                   result->password,
                                   result->currentTTL,
                                   result->ttlInfo[result->currentTTL].stunMsgId,
                                   result->sockfd,
                                   result->sendFunc,
                                   StunStatusCallBack,
                                   NULL );
      }else{
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
    }else{
      //do nothing
    }
  }
  else if ( (ICMPtype == 3) && (srcAddr->sa_family == AF_INET) )
  {
    /*Got port unreachable. We can stop now*/
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

      /* cancel any outstanding transactions */
      for (int i = ttl + 1; i <= result->currentTTL; i++)
      {
        printf("Canceling transaction (%i)\n", i);
        StunClient_cancelBindingTransaction( (STUN_CLIENT_DATA*)result->stunCtx,
                                             result->ttlInfo[i].stunMsgId );
      }
      resartIfNotDone(result);


    }
  }
  else
  {
    printf("   Some sort of ICMP message. Ignoring\n");
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
  (void) rtt;
  (void) ttl;
  (void)retransmits;
  /* TODO do callback here */
  /*
   *  printResultLine(out_format,
   *               true,
   *               ttl,
   *               srcAddr,
   *               rtt,
   *               retransmits);
   */
  /* printf("   RFLX addr: '%s'\n", */
  /*       sockaddr_toString(rflxAddr, */
  /*                         addr, */
  /*                         sizeof(addr), */
  /*                         true)); */

  /*Got STUN response. We can stop now*/
  if ( sockaddr_sameAddr( (struct sockaddr*)&result->remoteAddr,srcAddr ) )
  {
    /* TODO do callback here */
    /*
     *  stopAndExit(0);
     */
  }
  if (result->currentTTL < result->user_max_ttl)
  {
    while (result->pathElement[result->currentTTL].inactive &&
           result->currentTTL < result->path_max_ttl)
    {
      result->currentTTL++;
    }
    stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                     rand(), result->currentTTL);
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->ttlInfo[result->currentTTL].stunMsgId,
                               result->sockfd,
                               result->sendFunc,
                               StunStatusCallBack,
                               NULL );
  }

}



void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData)
{
  /* char               addr[SOCKADDR_MAX_STRLEN]; */
  struct hiutResult* result = (struct hiutResult*)userCtx;

  if (result->pathElement[stunCbData->ttl].gotAnswer)
  {
    printf("Got his one already! Ignoring (%i)\n", stunCbData->ttl);
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
    printf("Should not happen (Probably a cancel OK)\n");
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

  result->currentTTL = 1;
  result->userCtx    = userCtx;
  stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId, rand(), 1);
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
                                  result->ttlInfo[result->currentTTL].stunMsgId,
                                  result->sockfd,
                                  result->sendFunc,
                                  StunStatusCallBack,
                                  NULL);
  result->stunLen = len;

  return len;

}
