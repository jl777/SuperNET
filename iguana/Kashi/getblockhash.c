

/******************************************************************************
 *                                                                            *
 *                                                                            *
 * Using Brute force techinque program will randomly pick the block and       *
 * would compare is header hash. The expected header hashes for the blocks    *
 * are accurate and caculated using local bitcoind                            *
 *                                                                            *
 * All api calls are made on Iguana Core                                      *
 *                                                                            *
 ******************************************************************************/

#include<stdlib.h>
#include<string.h>
#include<assert.h>
#include<curl/curl.h>
#include<unistd.h>
#include<stdlib.h>
#define MAX_HEADER 45
#define STR_LEN   64
struct MemoryStruct 
{
  char *memory;
  size_t size;
};
 
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}



void fetchBlockHeader(const char * jsonrpc);
void bruteforceHashComparer();
int hash_index = 0;
int in=0;
int ind=0;
//char ActualHash[STR_LEN];
//char ExpectedHash[STR_LEN];
char *ActualHash;
char *ExpectedHash;

const char *hashes[MAX_HEADER] = 
                  {"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                   "0000000026f34d197f653c5e80cb805e40612eadb0f45d00d7ea4164a20faa33",
                   "000000007bc154e0fa7ea32218a72fe2c1bb9f86cf8c9ebf9a715ed27fdb229a",
                   "000000009ca75733b4cf527fe193b919201a2ed38c9e147a5665fdfade551f4d",
                   "000000008f1a7008320c16b8402b7f11e82951f44ca2663caf6860ab2eeef320",
                   "000000004e833644bc7fb021abd3da831c64ec82bae73042cfa63923d47d3303",
                   "0000000062b69e4a2c3312a5782d7798b0711e9ebac065cd5d19f946439f8609",
                   "00000000e286ad94972e44b0532f2823bcda3977661a5136ff4d9d7db107d944",
                   "000000002dd9919f0a67590bb7c945cb57270a060ce39e85d8d37536a71928c3",
                   "00000000e474895c09bcdaf9261845960b35ea54ed3ecaf60d8a392940f1f3f9",
                   "000000004ff664bfa7d217f6df64c1627089061429408e1da5ef903b8f3c77db",
                   "00000000314ff43c77573a3b8094951ce4b0f86aceee65e226914eb737ada575",
                   "00000000c7f956a913bbef9c94f517c318805821b59ea6227175f3841792ea88",
                   "00000000d3ebca0f1cf140987959ba9231e9da43f3f76aed02d0cfe9d88b71d7",
                   "0000000084d973c18381c87a63a2430ad2eff1d84934ec34e3bfd78ffd3cd9c1",
                   "00000000ad8174a71c1b2c01fd6076143c2cf57d768bf80d7c11b6721d3a2525",
                   "00000000def8545899ea7274e5c59bda5982f8f960052774df45b7d5c64f9c5d",
                   "00000000923a992877f070d2c8fa5ae67e66f6edcd828b321caa75885136386b",
                   "00000000e684309e67fabdf765bea193cdf8532111079b7f53a0839746d19240",
                   "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09",
                   "000000009cd3f93cd2d843202155561eb773b2a7b7c97561ddef31e707f4eb4b",
                   "00000000f0b6da96d1e3272e87e181a7057c3d79bf984b420d4f6fd6d7a49fc7",
                   "0000000047a712b762d9c91aa1cc2e33fb48ea64276a7086c3c10aa252a934ab",
                   "00000000c9c28d2bb760225beaddbc212a01720869b624f088e9311df5b5d8f2",
                   "000000007d07681a955b7bb9d96c473e847395b592b6e9e5a73b15b594bd4013",
                   "00000000f6b38fee667afb9cb2eedc5a9988d345e7b61ce220d34005d2d5b8bf",
                   "000000009bf03aa138b1bb31491261221f8d4562941c1022a798acda7e3158d4",
                   "00000000046d4e2de13c9a31dec05fafcae393ae7de773242abd4db47e9e747f",
                   "00000000e67f39a80dbba80e5bf130294ef460b89022c7a56c3df76ab2df2e71",
                   "00000000dfd5d65c9d8561b4b8f60a63018fe3933ecb131fb37f905f87da951a",
                   "00000000d5092034c3a92473d42f28e3fd279f0652e2d5b0049c7d40fcbc990b",
                   "0000000070118b55e0436a721d4533fc3d09a0238f72a5380e8a694c9dbf948e",
                   "0000000091a5fdf4b5f5fe07ed869bf82049b3d61a403f2771b5cbd1937dad09",
                   "00000000081038eb250216ebb27f94d8896d2984dc962020c53e6a2852b92967",
                   "00000000d84724559f1691d916b2ed63a44884d495d155197647ce7667116b16",
                   "0000000091a7488531bb1050f24c0f8f90d4da873673eb4dec62bbce56a32910",
                   "000000001731f7bb532ebd8ff11c253f128a9e3108eaf038d8155fedeba5bc0c",
                   "00000000d10250150162aefbf7d64ab10f3b4706ffe4d04ae59ca410f672e97b",
                   "00000000a4342e04aa766386cdb4da70137efd47ac271f1a4e18429af3020a7c",
                   "000000004a81b9aa469b11649996ecb0a452c16d1181e72f9f980850a1c5ecce",
                   "00000000bccaab487030fe7c0d8d66a80fefc157bd75f0de40b6b8d61ea1d287",     
                   "00000000b6641cc18693437c5208bf362730c533fd3ea4cca364793603bba957",
                   "00000000bfa35a68d94bf878a712c538484d8bc272c6ddd70de4e636d55f45de",
                   "00000000b590a5ff44afeb50e51444d8b6ccd08f6232951316f33e19b5ca5ff2",
                   "00000000922e2aa9e84a474350a3555f49f06061fd49df50a9352f156692a842"
                 };

const char *jsonRPC[MAX_HEADER] =
      { "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1] }",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [50] }",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [100]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [150]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [200]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [250]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [300]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [350]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [400]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [450]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [500]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [550]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [600]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [650]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [700]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [750]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [800]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [850]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [900]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1000]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1100]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1200]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1300]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1400]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1500]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1600]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1700]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1800]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [1900]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2000]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2100]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2200]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2300]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2400]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2500]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2600]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2700]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2800]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [2900]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [3000]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [3200]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [3400]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [3600]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [3800]}",
        "{\"id\":\"jl777\", \"method\": \"getblockhash\", \"params\": [4000]}"};



int main()
{
   int api;
   CURL *curl; 
   CURLcode res;

 //  struct MemoryStruct chunk;
 
  // chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  // chunk.size = 0;    /* no data at this point */
           
   // curl_global_init(CURL_GLOBAL_ALL);
    // initialize all sub modules and return an easy handle for upcoming easy transfer
 //   curl  = curl_easy_init();

    // raise an assertion if handle is NULL
    
       for(api=0; api<(MAX_HEADER-1); api++)
       {
      //   printf("api == %d\n",api);
         fetchBlockHeader(jsonRPC[api]);
       }



    return 0;
}

void fetchBlockHeader(const char* jsonrpc)
{
 
    CURL *curl;
   CURLcode res;
    struct MemoryStruct chunk;

   chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
   chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);
    // initialize all sub modules and return an easy handle for upcoming easy transfer
    curl  = curl_easy_init();

    if(curl == NULL)
    {
      assert(curl);
    }

   ActualHash = (char*)calloc(64,sizeof(char));
   ExpectedHash = (char*)calloc(64,sizeof(char));
   if(ActualHash == NULL)
   {
     printf("ERROR: memory allocation failed for ActualHash\n");
     exit(1);
   }

    if(ExpectedHash == NULL)
   {
     printf("ERROR: memory allocation failed for ExpectedHash\n");
     exit(1);
   }




   printf("\n");
   printf("RPC:%s\n\n",jsonrpc);
   // set the properties and options for curl 
 //   printf("1\n");
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:7778");

     /* send all data to this function  */ 
  //  printf("2\n");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 
  /* we pass our 'chunk' struct to the callback function */ 
   // printf("3\n");

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    // calculate the length of data that will be passed using POST method to server
  //  printf("4\n");

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(jsonrpc));

    // the data parameter should be a pointer to character
   // printf("5\n");

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonrpc);
 
    // request using SSL for the transfer, otherwise normal transfer
   // printf("6\n");

    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    //  printf("7\n");

    res =curl_easy_perform(curl);
    // printf("8\n");

  /* check for errors */ 
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }
  else 
  {
   //  printf("9\n");

    strcpy(ActualHash,chunk.memory);
   //remove space from string
/*
   while(ActualHash[in] !='\0')
   {
       if((ActualHash[in] != ' ')  (ActualHash[in+1] != ' '))
       {
          
          iguanaResp[ind] = ActualHash[in];
          ind++;
       }
       else
       {
          printf("Got whitespace\n");
       }
    in++;
   }
   iguanaResp[ind] = '\0';
*/
   //  printf("10\n");

    bruteforceHashComparer(curl);     
    
    
  }

    sleep(2);
  
    free(ActualHash);
   //   printf("11\n");

    free(ExpectedHash);
   //  printf("12\n");
    free(chunk.memory);
   // printf("13\n");

    in=0;
    ind=0;
   curl_easy_cleanup(curl);
   //printf("14\n");

    


} 

void bruteforceHashComparer()
{

   int ret;
   strcpy(ExpectedHash,hashes[hash_index]);
   printf("Expect Hash: %s\n",ExpectedHash);
   printf("Acutal Hash: %s\n",ActualHash);
   
   ret = strncmp(ExpectedHash,ActualHash,64);
   if(ret == 0)
   {
       printf("\t******************  PASSED ****************\n");
   }
  
   else
   {
      printf("\t******************  FAILED ****************\n");

   }

  hash_index++; 

  if(hash_index == MAX_HEADER)
  {
     hash_index = 0;
 //    curl_easy_cleanup(curl);
  }
  

}
