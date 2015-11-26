#pragma once

int
StunTrace_startTrace(STUN_CLIENT_DATA*      clientData,
                     const struct sockaddr* toAddr,
                     const struct sockaddr* fromAddr,
                     uint32_t               sockhandle,
                     const char*            ufrag,
                     const char*            password,
                     STUN_SENDFUNC          sendFunc);
