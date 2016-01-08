/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#define CHROMEAPP_NAME iguana
#define CHROMEAPP_STR "iguana"
#define CHROMEAPP_CONF "iguana.conf"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana

#include "../pnacl_main.h"
#include "iguana777.h"

// ALL globals must be here!
struct iguana_info *Coins[IGUANA_MAXCOINS];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
char NXTAPIURL[256],IGUANA_NXTADDR[256],IGUANA_NXTACCTSECRET[256];
uint64_t IGUANA_MY64BITS;
queue_t helperQ;
static int32_t initflag;
#ifdef __linux__
int32_t IGUANA_NUMHELPERS = 4;
#else
int32_t IGUANA_NUMHELPERS = 1;
#endif

#ifdef oldway
void *iguana(void *arg)
{
    if ( arg == 0 )
#ifdef __linux__
        arg = 0;//"{\"coins\":[{\"name\":\"BTCD\",\"maxpeers\":128,\"initialheight\":400000,\"services\":1,\"peers\":[\"127.0.0.1\"]}]}";
        //arg = "{\"coins\":[{\"name\":\"BTCD\",\"services\":1,\"maxrecvcache\":64,\"peers\":[\"127.0.0.1\",\"107.170.13.184\",\"108.58.252.82\",\"207.182.151.130\",\"70.106.255.189\"]}]}";
#else
        arg = 0;//"{\"coins\":[{\"name\":\"BTCD\",\"maxpeers\":128,\"initialheight\":400000,\"services\":1,\"peers\":[\"127.0.0.1\"]}]}";
#endif
    PostMessage("iguana start.(%s)\n",(char *)arg);
    while ( initflag == 0 )
        sleep(1);
    iguana_main(arg);
    return(0);
}

#ifdef __PNACL
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/stat.h>
#include "includes/ppapi/c/ppb.h"
#include "includes/ppapi/c/ppb_var.h"
#include "includes/ppapi/c/ppb_instance.h"
#include "includes/ppapi/c/ppb_messaging.h"
#include "includes/ppapi/c/ppb_var_array.h"
#include "includes/ppapi/c/ppb_var_dictionary.h"
#include "includes/ppapi/c/pp_errors.h"
#include "includes/ppapi/c/ppp_messaging.h"
#include "includes/ppapi/c/ppp_instance.h"
typedef int (*PSMainFunc_t)(int argc, char *argv[]);

#if defined(WIN32)
#define va_copy(d, s) ((d) = (s))
#endif

#ifndef __PNACL
int32_t PSGetInstanceId()
{
    return(4);
}
#endif

typedef int (*HandleFunc)(struct PP_Var params,struct PP_Var* out_var,const char** error);
typedef struct { const char* name; HandleFunc function; } FuncNameMapping;
static PP_Instance g_instance = 0;
static PPB_GetInterface g_get_browser_interface = NULL;
static PPB_Messaging* g_ppb_messaging = NULL;
PPB_Var* g_ppb_var = NULL;
PPB_VarArray* g_ppb_var_array = NULL;
PPB_VarDictionary* g_ppb_var_dictionary = NULL;
int Handle_iguana(struct PP_Var params,struct PP_Var *output,const char **out_error);
static FuncNameMapping g_function_map[] = { { "iguana", Handle_iguana }, { NULL, NULL } };
struct PP_Var CStrToVar(const char* str) { return g_ppb_var->VarFromUtf8(str, (int32_t)strlen(str)); }

char *VprintfToNewString(const char* format, va_list args)
{
    va_list args_copy; int length; char *buffer; int result;
    va_copy(args_copy, args);
    length = vsnprintf(NULL, 0, format, args);
    buffer = (char*)malloc(length + 1); // +1 for NULL-terminator.
    result = vsnprintf(&buffer[0], length + 1, format, args_copy);
    if ( result != length )
    {
        assert(0);
        return NULL;
    }
    return buffer;
}

char *PrintfToNewString(const char *format, ...)
{
    va_list args; char *result;
    va_start(args, format);
    result = VprintfToNewString(format, args);
    va_end(args);
    return result;
}

struct PP_Var VprintfToVar(const char* format, va_list args)
{
    struct PP_Var var; char *string = VprintfToNewString(format, args);
    var = g_ppb_var->VarFromUtf8(string, (int32_t)strlen(string));
    free(string);
    return var;
}

static const char *VarToCStr(struct PP_Var var)
{
    uint32_t length; char *new_str; const char *str = g_ppb_var->VarToUtf8(var, &length);
    if ( str == NULL )
        return NULL;
    new_str = (char*)malloc(length + 1);
    memcpy(new_str, str, length); // str is NOT NULL-terminated. Copy using memcpy.
    new_str[length] = 0;
    return new_str;
}

struct PP_Var GetDictVar(struct PP_Var dict, const char* key)
{
    struct PP_Var key_var = CStrToVar(key);
    struct PP_Var value = g_ppb_var_dictionary->Get(dict, key_var);
    g_ppb_var->Release(key_var);
    return value;
}

void PostMessage(const char* format, ...)
{
    va_list args;
    va_start(args, format);
#ifdef __PNACL
    struct PP_Var var;
    var = VprintfToVar(format, args);
    g_ppb_messaging->PostMessage(g_instance, var);
    g_ppb_var->Release(var);
#else
    printf(format,args);
#endif
    va_end(args);
}

/**
 * Given a message from JavaScript, parse it for functions and parameters.
 *
 * The format of the message is:
 * {
 *  "cmd": <function name>,
 *  "args": [<arg0>, <arg1>, ...]
 * }
 *
 * @param[in] message The message to parse.
 * @param[out] out_function The function name.
 * @param[out] out_params A PP_Var array.
 * @return 0 if successful, otherwise 1.
 */
static int ParseMessage(struct PP_Var message,const char **out_function,struct PP_Var *out_params)
{
    if ( message.type != PP_VARTYPE_DICTIONARY )
        return(1);
    struct PP_Var cmd_value = GetDictVar(message, "cmd");
    *out_function = VarToCStr(cmd_value);
    g_ppb_var->Release(cmd_value);
    *out_params = GetDictVar(message, "args");
    PostMessage("Parse.(%s) cmd.(%s)\n",*out_function,VarToCStr(*out_params));
    if ( cmd_value.type != PP_VARTYPE_STRING )
        return(1);
    if ( out_params->type != PP_VARTYPE_ARRAY )
        return(1);
    return(0);
}

static HandleFunc GetFunctionByName(const char* function_name)
{
    FuncNameMapping* map_iter = g_function_map;
    for (; map_iter->name; ++map_iter)
    {
        if (strcmp(map_iter->name, function_name) == 0)
            return map_iter->function;
    }
    return NULL;
}

/**
 * Handle as message from JavaScript on the worker thread.
 *
 * @param[in] message The message to parse and handle.
 */
static void HandleMessage(struct PP_Var message)
{
    const char *function_name,*error; struct PP_Var params,result_var;
    if ( ParseMessage(message, &function_name, &params) != 0 )
    {
        PostMessage("Error: Unable to parse message");
        return;
    }
    HandleFunc function = GetFunctionByName(function_name);
    if ( function == 0 )
    {
        PostMessage("Error: Unknown function \"%s\"", function_name); // Function name wasn't found.
        return;
    }
    // Function name was found, call it.
    int result = (*function)(params, &result_var, &error);
    if ( result != 0 )
    {
        if ( error != NULL )
        {
            PostMessage("Error: \"%s\" failed: %s.", function_name, error);
            free((void*)error);
        }
        else PostMessage("Error: \"%s\" failed.", function_name);
        return;
    }
    // Function returned an output dictionary. Send it to JavaScript.
    g_ppb_messaging->PostMessage(g_instance, result_var);
    g_ppb_var->Release(result_var);
}

#define MAX_QUEUE_SIZE 256

// A mutex that guards |g_queue|.
static pthread_mutex_t g_queue_mutex;
// A condition variable that is signalled when |g_queue| is not empty.
static pthread_cond_t g_queue_not_empty_cond;

/** A circular queue of messages from JavaScript to be handled.
 *
 * If g_queue_start < g_queue_end:
 *   all elements in the range [g_queue_start, g_queue_end) are valid.
 * If g_queue_start > g_queue_end:
 *   all elements in the ranges [0, g_queue_end) and
 *   [g_queue_start, MAX_QUEUE_SIZE) are valid.
 * If g_queue_start == g_queue_end, and g_queue_size > 0:
 *   all elements in the g_queue are valid.
 * If g_queue_start == g_queue_end, and g_queue_size == 0:
 *   No elements are valid. */
static struct PP_Var g_queue[MAX_QUEUE_SIZE];
static int g_queue_start = 0; // The index of the head of the queue
static int g_queue_end = 0; // The index of the tail of the queue, non-inclusive.
static int g_queue_size = 0;
// NOTE: this function assumes g_queue_mutex lock is held. @return non-zero if the queue is empty
static int IsQueueEmpty() { return g_queue_size == 0; }
// NOTE: this function assumes g_queue_mutex lock is held. @return non-zero if the queue is full
static int IsQueueFull() { return g_queue_size == MAX_QUEUE_SIZE; }

void InitializeMessageQueue()
{
    pthread_mutex_init(&g_queue_mutex, NULL);
    pthread_cond_init(&g_queue_not_empty_cond, NULL);
}

int EnqueueMessage(struct PP_Var message)
{
    pthread_mutex_lock(&g_queue_mutex);
    // We shouldn't block the main thread waiting for the queue to not be full, so just drop the message.
    if ( IsQueueFull() != 0)
    {
        PostMessage("EnqueueMessage: full Q, drop message\n");
        pthread_mutex_unlock(&g_queue_mutex);
        return(0);
    }
    g_queue[g_queue_end] = message;
    g_queue_end = (g_queue_end + 1) % MAX_QUEUE_SIZE;
    g_queue_size++;
    pthread_cond_signal(&g_queue_not_empty_cond);
    pthread_mutex_unlock(&g_queue_mutex);
    return 1;
}

struct PP_Var DequeueMessage()
{
    struct PP_Var message;
    pthread_mutex_lock(&g_queue_mutex);
    while ( IsQueueEmpty() != 0 )
        pthread_cond_wait(&g_queue_not_empty_cond, &g_queue_mutex);
    message = g_queue[g_queue_start];
    g_queue_start = (g_queue_start + 1) % MAX_QUEUE_SIZE;
    g_queue_size--;
    pthread_mutex_unlock(&g_queue_mutex);
    return(message);
}

/**
 * A worker thread that handles messages from JavaScript.
 * @param[in] user_data Unused.
 * @return unused.
 */
void *HandleMessageThread(void *user_data)
{
    while ( 1 )
    {
        struct PP_Var message = DequeueMessage();
        HandleMessage(message);
        g_ppb_var->Release(message);
    }
}

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef mount
#undef umount

static PP_Bool Instance_DidCreate(PP_Instance instance,uint32_t argc,const char* argn[],const char* argv[])
{
    int nacl_io_init_ppapi(PP_Instance instance, PPB_GetInterface get_interface);
    static pthread_t g_handle_message_thread;
    static pthread_t iguana_thread;
    int64_t allocsize;
    g_instance = instance;
    // By default, nacl_io mounts / to pass through to the original NaCl
    // filesystem (which doesn't do much). Let's remount it to a memfs
    // filesystem.
    InitializeMessageQueue();
    pthread_create(&g_handle_message_thread, NULL, &HandleMessageThread, NULL);
    pthread_create(&iguana_thread,NULL,&iguana,OS_filestr(&allocsize,"iguana.conf"));
    nacl_io_init_ppapi(instance,g_get_browser_interface);
    umount("/");
    mount("", "/memfs", "memfs", 0, "");
    mount("",                                       /* source */
          "/",                            /* target */
          "html5fs",                                /* filesystemtype */
          0,                                        /* mountflags */
          "type=PERSISTENT,expected_size=10000000000"); /* data */
    mount("",       /* source. Use relative URL */
          "/http",  /* target */
          "httpfs", /* filesystemtype */
          0,        /* mountflags */
          "");      /* data */
    PostMessage("finished DidCreate\n");
    initflag = 1;
    return PP_TRUE;
}

static void Instance_DidDestroy(PP_Instance instance) { }

static void Instance_DidChangeView(PP_Instance instance,PP_Resource view_resource) { }

static void Instance_DidChangeFocus(PP_Instance instance, PP_Bool has_focus) { }

static PP_Bool Instance_HandleDocumentLoad(PP_Instance instance,PP_Resource url_loader)
{
    // NaCl modules do not need to handle the document load function.
    return PP_FALSE;
}

static void Messaging_HandleMessage(PP_Instance instance,struct PP_Var message)
{
    if ( message.type != PP_VARTYPE_DICTIONARY ) // Special case for jspipe input handling
    {
        PostMessage("Got unexpected message type: %d\n", message.type);
        return;
    }
    struct PP_Var pipe_var = CStrToVar("pipe");
    struct PP_Var pipe_name = g_ppb_var_dictionary->Get(message, pipe_var);
    g_ppb_var->Release(pipe_var);
    if ( pipe_name.type == PP_VARTYPE_STRING ) // Special case for jspipe input handling
    {
        char file_name[PATH_MAX];
        snprintf(file_name, PATH_MAX, "/dev/%s", VarToCStr(pipe_name));
        int fd = open(file_name, O_RDONLY);
        g_ppb_var->Release(pipe_name);
        if ( fd < 0 )
        {
            PostMessage("Warning: opening %s failed.", file_name);
            goto done;
        }
        //if ( ioctl(fd, NACL_IOC_HANDLEMESSAGE, &message) != 0 )
        //    PostMessage("Error: ioctl on %s failed: %s", file_name, strerror(errno));
        close(fd);
        goto done;
    }
    g_ppb_var->AddRef(message);
    if ( !EnqueueMessage(message) )
    {
        g_ppb_var->Release(message);
        PostMessage("Warning: dropped message because the queue was full.");
    }
done:
    g_ppb_var->Release(pipe_name);
}

#define GET_INTERFACE(var, type, name)            \
var = (type*)(get_browser(name));               \
if (!var) {                                     \
printf("Unable to get interface " name "\n"); \
return PP_ERROR_FAILED;                       \
}

//PP_EXPORT
int32_t PPP_InitializeModule(PP_Module a_module_id,PPB_GetInterface get_browser)
{
    g_get_browser_interface = get_browser;
    GET_INTERFACE(g_ppb_messaging, PPB_Messaging, PPB_MESSAGING_INTERFACE);
    GET_INTERFACE(g_ppb_var, PPB_Var, PPB_VAR_INTERFACE);
    GET_INTERFACE(g_ppb_var_array, PPB_VarArray, PPB_VAR_ARRAY_INTERFACE);
    GET_INTERFACE(g_ppb_var_dictionary, PPB_VarDictionary, PPB_VAR_DICTIONARY_INTERFACE);
    return PP_OK;
}

//PP_EXPORT
const void *PPP_GetInterface(const char* interface_name)
{
    if ( strcmp(interface_name,PPP_INSTANCE_INTERFACE) == 0 )
    {
        static PPP_Instance instance_interface =
        {
            &Instance_DidCreate,
            &Instance_DidDestroy,
            &Instance_DidChangeView,
            &Instance_DidChangeFocus,
            &Instance_HandleDocumentLoad,
        };
        return &instance_interface;
    }
    else if ( strcmp(interface_name, PPP_MESSAGING_INTERFACE) == 0 )
    {
        static PPP_Messaging messaging_interface = { &Messaging_HandleMessage };
        return &messaging_interface;
    }
    return NULL;
}

//PP_EXPORT
void PPP_ShutdownModule() { }

#define CHECK_PARAM_COUNT(name, expected)                                   \
if (GetNumParams(params) != expected) {                                   \
*out_error = PrintfToNewString(#name " takes " #expected " parameters." \
" Got %d", GetNumParams(params));        \
return 1;                                                               \
}

#define PARAM_STRING(index, var)                                    \
char* var;                                                        \
uint32_t var##_len;                                               \
if (GetParamString(params, index, &var, &var##_len, out_error)) { \
return 1;                                                       \
}

#define CREATE_RESPONSE(name) CreateResponse(output, #name, out_error)
#define RESPONSE_STRING(var) AppendResponseString(output, var, out_error)
#define RESPONSE_INT(var) AppendResponseInt(output, var, out_error)
#define MAX_PARAMS 4
static char* g_ParamStrings[MAX_PARAMS];
/**
 * Get the number of parameters.
 * @param[in] params The parameter array.
 * @return uint32_t The number of parameters in the array.
 */
static uint32_t GetNumParams(struct PP_Var params) {
    return g_ppb_var_array->GetLength(params);
}


/**
 * Create a response PP_Var to send back to JavaScript.
 * @param[out] response_var The response PP_Var.
 * @param[in] cmd The name of the function that is being executed.
 * @param[out] out_error An error message, if this call failed.
 */
static void CreateResponse(struct PP_Var* response_var,
                           const char* cmd,
                           const char** out_error) {
    PP_Bool result;
    
    struct PP_Var dict_var = g_ppb_var_dictionary->Create();
    struct PP_Var cmd_key = CStrToVar("cmd");
    struct PP_Var cmd_value = CStrToVar(cmd);
    
    result = g_ppb_var_dictionary->Set(dict_var, cmd_key, cmd_value);
    g_ppb_var->Release(cmd_key);
    g_ppb_var->Release(cmd_value);
    
    if (!result) {
        g_ppb_var->Release(dict_var);
        *out_error =
        PrintfToNewString("Unable to set \"cmd\" key in result dictionary");
        return;
    }
    
    struct PP_Var args_key = CStrToVar("args");
    struct PP_Var args_value = g_ppb_var_array->Create();
    result = g_ppb_var_dictionary->Set(dict_var, args_key, args_value);
    g_ppb_var->Release(args_key);
    g_ppb_var->Release(args_value);
    
    if (!result) {
        g_ppb_var->Release(dict_var);
        *out_error =
        PrintfToNewString("Unable to set \"args\" key in result dictionary");
        return;
    }
    
    *response_var = dict_var;
}
/**
 * Append a PP_Var to the response dictionary.
 * @param[in,out] response_var The response PP_var.
 * @param[in] value The value to add to the response args.
 * @param[out] out_error An error message, if this call failed.
 */
static void AppendResponseVar(struct PP_Var* response_var,
                              struct PP_Var value,
                              const char** out_error) {
    struct PP_Var args_value = GetDictVar(*response_var, "args");
    uint32_t args_length = g_ppb_var_array->GetLength(args_value);
    PP_Bool result = g_ppb_var_array->Set(args_value, args_length, value);
    if (!result) {
        // Release the dictionary that was there before.
        g_ppb_var->Release(*response_var);
        
        // Return an error message instead.
        *response_var = PP_MakeUndefined();
        *out_error = PrintfToNewString("Unable to append value to result");
        return;
    }
}

/**
 * Append a string to the response dictionary.
 * @param[in,out] response_var The response PP_var.
 * @param[in] value The value to add to the response args.
 * @param[out] out_error An error message, if this call failed.
 */
static void AppendResponseString(struct PP_Var* response_var,
                                 const char* value,
                                 const char** out_error) {
    struct PP_Var value_var = CStrToVar(value);
    AppendResponseVar(response_var, value_var, out_error);
    g_ppb_var->Release(value_var);
}

/**
 * Get a parameter at |index| as a string.
 * @param[in] params The parameter array.
 * @param[in] index The index in |params| to get.
 * @param[out] out_string The output string.
 * @param[out] out_string_len The length of the output string.
 * @param[out] out_error An error message, if this operation failed.
 * @return int 0 if successful, otherwise 1.
 */
static int GetParamString(struct PP_Var params,
                          uint32_t index,
                          char** out_string,
                          uint32_t* out_string_len,
                          const char** out_error) {
    if (index >= MAX_PARAMS) {
        *out_error = PrintfToNewString("Param index %u >= MAX_PARAMS (%d)",
                                       index, MAX_PARAMS);
        return 1;
    }
    
    struct PP_Var value = g_ppb_var_array->Get(params, index);
    if (value.type != PP_VARTYPE_STRING) {
        *out_error =
        PrintfToNewString("Expected param at index %d to be a string not.%d", index,value.type);
        return 1;
    }
    
    uint32_t length;
    const char* var_str = g_ppb_var->VarToUtf8(value, &length);
    
    char* string = (char*)malloc(length + 1);
    memcpy(string, var_str, length);
    string[length] = 0;
    
    /* Put the allocated string in g_ParamStrings. This keeps us from leaking
     * each parameter string, without having to do manual cleanup in every
     * Handle* function below.
     */
    free(g_ParamStrings[index]);
    g_ParamStrings[index] = string;
    
    
    *out_string = string;
    *out_string_len = length;
    return 0;
}

int Handle_iguana(struct PP_Var params,struct PP_Var *output,const char **out_error)
{
    char *iguana_JSON(char *);
    char *retstr;
    PostMessage("inside Handle_iguana\n");
    CHECK_PARAM_COUNT(iguana, 1);
    PARAM_STRING(0,jsonstr);
    retstr = iguana_JSON(jsonstr);
    CREATE_RESPONSE(iguana);
    RESPONSE_STRING(retstr);
    return 0;
}

int example_main()
{
    PostMessage("Started example main.\n");
    //g_pInputEvent = (PPB_InputEvent*) PSGetInterface(PPB_INPUT_EVENT_INTERFACE);
    //g_pKeyboardInput = (PPB_KeyboardInputEvent*)PSGetInterface(PPB_KEYBOARD_INPUT_EVENT_INTERFACE);
    //g_pMouseInput = (PPB_MouseInputEvent*) PSGetInterface(PPB_MOUSE_INPUT_EVENT_INTERFACE);
    //g_pTouchInput = (PPB_TouchInputEvent*) PSGetInterface(PPB_TOUCH_INPUT_EVENT_INTERFACE);
    //PSEventSetFilter(PSE_ALL);
    while ( 1 )
    {
        sleep(777);
        /* Process all waiting events without blocking
         PSEvent* event;
         while ((event = PSEventTryAcquire()) != NULL) {
         ProcessEvent(event);
         PSEventRelease(event);
         }*/
    }
    return 0;
}

PSMainFunc_t PSUserMainGet()
{
    return(example_main);
}
#else
int main(int argc, const char * argv[])
{
    char *jsonstr;
    if ( argc < 2 )
        jsonstr = 0;
    else jsonstr = (char *)argv[1];
    initflag = 1;
    printf("main\n");
    iguana(jsonstr);
    return 0;
}
#endif
#endif
