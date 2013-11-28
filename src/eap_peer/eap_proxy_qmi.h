/*--------------------------------------------------------------------------
Copyright (c) 2013, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--------------------------------------------------------------------------*/

#ifndef EAP_PROXY_QMI_H
#define EAP_PROXY_QMI_H


#include "eap_i.h"
#include "eap_config.h"
#include "eloop.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "user_identity_module_v01.h"

/*msec Response Timeout*/
#define QMI_RESP_TIME_OUT 2000
#define EAP_PROXY_KEYING_DATA_LEN 64

#ifdef CONFIG_EAP_PROXY_DUAL_SIM
#define MAX_NO_OF_SIM_SUPPORTED 2
#else
#define MAX_NO_OF_SIM_SUPPORTED 1
#endif /* CONFIG_EAP_PROXY_DUAL_SIM */

typedef enum {
        QMI_STATE_IDLE = 0x00,
        QMI_STATE_RESP_PENDING  = 0x01,
        QMI_STATE_RESP_RECEIVED = 0x02,
        QMI_STATE_RESP_TIME_OUT = 0x03
} qmi_state_e;

typedef enum {
        EAP_PROXY_QMI_SRVC_NO_RESULT,
        EAP_PROXY_QMI_SRVC_SUCCESS,
        EAP_PROXY_QMI_SRVC_FAILURE
} eap_proxy_qmi_srv_result;

/* should match the EAP_state  of eap_i.h */
typedef enum {
        EAP_PROXY_INITIALIZE, EAP_PROXY_DISABLED, EAP_PROXY_IDLE, EAP_PROXY_RECEIVED,
        EAP_PROXY_GET_METHOD, EAP_PROXY_METHOD, EAP_PROXY_SEND_RESPONSE,
        EAP_PROXY_DISCARD, EAP_PROXY_IDENTITY, EAP_PROXY_NOTIFICATION,
        EAP_PROXY_RETRANSMIT,
        EAP_PROXY_AUTH_SUCCESS,  EAP_PROXY_AUTH_FAILURE
} eap_proxy_state;


enum eap_proxy_status {
        EAP_PROXY_FAILURE = 0x00,
        EAP_PROXY_SUCCESS
};

typedef enum {
        EAP_IDENTITY_ANNONYMOUS = 0x00,
        EAP_IDENTITY_IMSI_RAW  = 0x02,
        EAP_IDENTITY_IMSI_3GPP_REALM = 0x03,
        EAP_IDENTITY_IMSI_REALM = 0x04,
        EAP_IDENTITY_CFG_RAW = 0x05,
        EAP_IDENTITY_CFG_3GPP_REALM = 0x06,
        EAP_IDENTITY_CFG_REALM = 0x07,
} eap_identity_format_e;

typedef union
{
        struct
        {
                void *resp_data; /* Pointer to the Response Packet*/
                unsigned long length;     /*Length of the Response Packet*/
        }eap_send_pkt_resp;

}qmi_eap_sync_rsp_data_type;

typedef struct {
        uim_card_state_enum_v01                      card_state;
        uim_card_error_code_enum_v01                 card_error_code;
        u8                                           app_state;
        u8                                           app_type;
} wpa_uim_card_info_type;

typedef struct {
        int                                   card_ready_idx;
        wpa_uim_card_info_type                card_info[QMI_UIM_CARDS_MAX_V01];
        qmi_client_type                       qmi_uim_svc_client_ptr;
        int                                   qmi_msg_lib_handle;
} wpa_uim_struct_type;


struct eap_proxy_sm {
        qmi_client_type qmi_auth_svc_client_ptr[MAX_NO_OF_SIM_SUPPORTED];
        qmi_state_e qmi_state;
        eap_proxy_qmi_srv_result srvc_result;
        qmi_eap_sync_rsp_data_type qmi_resp_data;
        eap_proxy_state  proxy_state;
        Boolean iskey_valid;
        u8 *key;
        Boolean is_state_changed;
        void *ctx;
        void *msg_ctx;
        struct eapol_callbacks *eapol_cb;
        u8 *eapReqData;
        size_t eapReqDataLen;
        Boolean isEap;
        int eap_type;
        int user_selected_sim;
        int eap_auth_session_flag[MAX_NO_OF_SIM_SUPPORTED];
        int notification_code;
        pthread_t thread_id;
        wpa_uim_struct_type   wpa_uim[MAX_NO_OF_SIM_SUPPORTED];
        Boolean qmi_uim_svc_client_initialized[MAX_NO_OF_SIM_SUPPORTED];
};

int eap_proxy_allowed_method(struct eap_peer_config *config, int vendor,
                              u32 method);

#endif /* EAP_PROXY_QMI_H */
