#define DECLARE_MODULE(name) &(g_rtp_##name##_module),

#ifdef USE_MODULE_COMMON
DECLARE_MODULE(nack)
DECLARE_MODULE(audio)
DECLARE_MODULE(video)
DECLARE_MODULE(rtcp)
#endif //USE_MODULE_COMMON

#ifdef USE_MODULE_AUDIO
#endif //USE_MODULE_AUDIO

#ifdef USE_MODULE_VIDEO
DECLARE_MODULE(h264)
#endif //USE_MODULE_VIDEO

#ifdef USE_MODULE_H264
#endif //USE_MODULE_H264

#ifdef USE_MODULE_RTCP
#endif //USE_MODULE_RTCP

