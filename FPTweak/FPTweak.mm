//
//  FPTweak.m
//  FPTweak
//
//  Created by h4ck on 2019/3/27.
//  Copyright (c) 2019年 猿码工作室（https://ymlab.net）. All rights reserved.
//

#import "FPTweak.h"
#import <CaptainHook/CaptainHook.h>
#import <substrate.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <mach/task.h>

#pragma mark - Jailbreak fake

static bool isBlackListPath(const char *path)
{
    static const char *black_list[] = {
        "/var/lib/cydia/",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/bin/sw",
        "/etc/apt",
        "/etc/apt/",
        "/var/cache/apt",
        "/var/cache/apt/",
        "/var/lib/apt",
        "/var/lib/apt/",
        "/var/log/syslog",
        "/etc/clutch.conf",
        "/var/cache/clutch.plist",
        "/etc/clutch_cracked.plist",
        "/var/cache/clutch_cracked.plist",
        "/var/lib/clutch/overdrive.dylib",
        "/var/root/Documents/Cracked/",
        "/usr/libexec/cydia/",
        "/usr/libexec/ssh-keysign",
        "/bin/sh",
        "/etc/ssh/sshd_config",
        "/User/Applications/",
        "/Applications/blackra1n.app",
        "/private/var/lib/apt",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia",
        "/private/var/lib/cydia/",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/stash/",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/Applications/Cycorder.app",
        "/Applications/Loader.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
    };
    
    static const char *match_list[] ={
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate",
    };
    
    for (int i = 0; i < sizeof(match_list)/sizeof(match_list[0]); ++i) {
        if (strnstr(path,match_list[i],strlen(match_list[i]))) {
            return true;
        }
    }
    
    for (int i = 0; i < sizeof(black_list)/sizeof(black_list[0]); ++i) {
        if (strncmp(black_list[i], path, strlen(black_list[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

MSHook(FILE    *, fopen, const char * __restrict __filename, const char * __restrict __mode)
{
    if (__filename) {
        if (isBlackListPath(__filename)) {
            return NULL;
        }
    }
    
    return _fopen(__filename,__mode);
}

MSHook(int, system, const char *arg1)
{
    if (arg1 == NULL) {
        return 0;
    }
    
    return _system(arg1);
}

MSHook(int, stat, const char *path, struct stat *stat)
{
    if (path) {
        if (strncmp(path, "/etc/fstab", strlen("/etc/fstab")) == 0) {
            int ret = _stat(path,stat);
            if (stat != NULL) {
                stat->st_size = 80;
            }
            return ret;
        }else if (isBlackListPath(path)) {
            return -1;
        }
    }
    
    return _stat(path,stat);
}

static bool isBlackListLinkPath(const char *path)
{
    static const char *black_list[] = {
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
    };
    
    for (int i = 0; i < sizeof(black_list)/sizeof(black_list[0]); ++i) {
        if (strncmp(black_list[i], path, strlen(black_list[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

MSHook(int, lstat, const char *path, struct stat *b)
{
    int ret = _lstat(path,b);
    if (path) {
        if (isBlackListLinkPath(path) && b != NULL) {
            b->st_mode &= (~ S_IFLNK);
        }
    }
    return ret;
}

MSHook(int, isatty, int a)
{
    return 0;
    //    return _isatty(a);
}

MSHook(kern_return_t, task_get_exception_ports, task_t task,
       exception_mask_t exception_mask,
       exception_mask_array_t masks,
       mach_msg_type_number_t *masksCnt,
       exception_handler_array_t old_handlers,
       exception_behavior_array_t old_behaviors,
       exception_flavor_array_t old_flavors)
{
    return 1;
    //    return _task_get_exception_ports(task,exception_mask,masks,masksCnt,old_handlers,old_behaviors,old_flavors);
}

MSHook(char    *, getenv, const char *env)
{
    if (env)
    {
        if (strncmp("DYLD_INSERT_LIBRARIES", env, strlen("DYLD_INSERT_LIBRARIES")) == 0) {
            return NULL;
        }
    }
    
    return _getenv(env);
}

MSHook(const char *, _dyld_get_image_name,uint32_t image_index)
{
    const char *name = __dyld_get_image_name(image_index);
    if (name && strstr(name, "Substrate")) {
        // 创建伪全局变量
        static char *buffer = NULL;
        if (!buffer) {
            const char *src = "/usr/lib/libobjc.A.dylib";
            size_t len = strlen(src) + 1;
            buffer = (char *)calloc(len, sizeof(char));
            memset(buffer, 0, len);
            strncpy(buffer, src, len);
        }
        return buffer;
    }
    
    return name;
}

MSClassHook(NSFileManager)
MSInstanceMessage1(BOOL,NSFileManager,fileExistsAtPath,NSString *,path)
{
    if (path.length)
    {
        if (isBlackListPath(path.UTF8String)) {
            return NO;
        }
    }
    
    return MSOldCall(path);
}

MSInstanceMessage2(NSArray *,NSFileManager,contentsOfDirectoryAtPath,error,NSString *,path,NSError **,error)
{
    if (path.length)
    {
        if ([path isEqualToString:@"/Applications"] || [path isEqualToString:@"/Applications/"]) {
            return [NSArray array];
        }
    }
    return MSOldCall(path,error);
}

MSInstanceMessage2(NSArray *,NSFileManager,subpathsOfDirectoryAtPath,error,NSString *,path,NSError **,error)
{
    if (path.length)
    {
        if ([path isEqualToString:@"/Applications"] || [path isEqualToString:@"/Applications/"]) {
            return [NSArray array];
        }
    }
    
    return MSOldCall(path,error);
}


MSInstanceMessage2(BOOL,NSFileManager,fileExistsAtPath,isDirectory,NSString *,path,BOOL *,isDirectory)
{
    if (path.length)
    {
        if (isBlackListPath(path.UTF8String)) {
            return NO;
        }
    }
    return MSOldCall(path,isDirectory);
}

MSClassHook(UIApplication)
MSInstanceMessage1(BOOL,UIApplication,canOpenURL,NSURL *,url)
{
    if (url.absoluteString.length)
    {
        if ([url.absoluteString rangeOfString:@"cydia://"].location != NSNotFound)
        {
            return NO;
        }
    }
    
    return MSOldCall(url);
}

static bool isBlackListProcess(const char *name)
{
    static const char *black_list[] = {
        "Cydia",
        "MobileCydia",
        "afpd",
        "sshd",
        "afc2d",
    };
    
    for (int i = 0; i < sizeof(black_list)/sizeof(black_list[0]); ++i) {
        if (strncmp(black_list[i], name, strlen(black_list[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

MSHook(int, sysctl, int *arg1, u_int arg2, void *arg3, size_t *arg4, void *arg5, size_t arg6)
{
    int code = _sysctl(arg1,arg2,arg3,arg4,arg5,arg6);
    
    if (arg1[0] == CTL_KERN && arg1[1] == KERN_PROC && arg1[2] == KERN_PROC_ALL)
    {
        if (arg3 != NULL) {
            size_t count = *arg4 / sizeof(struct kinfo_proc);
            struct kinfo_proc *proc = (struct kinfo_proc *)arg3;
            for (int i = 0; i < count; ++i)
            {
                if (isBlackListProcess(proc[i].kp_proc.p_comm)) {
                    strncpy(proc[i].kp_proc.p_comm,"sandboxd",strlen("sandboxd")); // 将黑名单内的名字全部换成sandboxd
                }
            }
        }
    }
    return code;
}

MSHook(int, dladdr, const void *arg1, Dl_info *arg2)
{
    int ret = _dladdr(arg1,arg2);
    if (arg2 != NULL) {
        if (arg1 == $stat || arg1 == $task_get_exception_ports || arg1 == $lstat) {
            static char *buffer = NULL;
            if (!buffer) {
                const char *src = "/usr/lib/system/libsystem_kernel.dylib";
                size_t len = strlen(src) + 1;
                buffer = (char *)calloc(len, sizeof(char));
                memset(buffer, 0, len);
                strncpy(buffer, src, len);
            }
            arg2->dli_fname = buffer;
        }
        else if (arg1 == $getenv || arg1 == $fopen || arg1 == $isatty)
        {
            static char *buffer = NULL;
            if (!buffer) {
                const char *src = "/usr/lib/system/libsystem_c.dylib";
                size_t len = strlen(src) + 1;
                buffer = (char *)calloc(len, sizeof(char));
                memset(buffer, 0, len);
                strncpy(buffer, src, len);
            }
            arg2->dli_fname = buffer;
        }
        else if (arg1 == $NSFileManager$fileExistsAtPath$ || arg1 == $NSFileManager$fileExistsAtPath$isDirectory$)
        {
            static char *buffer = NULL;
            if (!buffer) {
                const char *src = "/System/Library/Frameworks/Foundation.framework/Foundation";
                size_t len = strlen(src) + 1;
                buffer = (char *)calloc(len, sizeof(char));
                memset(buffer, 0, len);
                strncpy(buffer, src, len);
            }
            arg2->dli_fname = buffer;
        }
        else if (arg1 == $_dyld_get_image_name)
        {
            static char *buffer = NULL;
            if (!buffer) {
                const char *src = "/usr/lib/system/libdyld.dylib";
                size_t len = strlen(src) + 1;
                buffer = (char *)calloc(len, sizeof(char));
                memset(buffer, 0, len);
                strncpy(buffer, src, len);
            }
            arg2->dli_fname = buffer;
        }
    }
    
    return ret;
}

CHConstructor
{
    NSLog(@"++++++++ FPTweak loaded ++++++++");
    
    MSHookFunction((void *)dladdr, MSHake(dladdr));
    MSHookFunction((void *)system, MSHake(system));
    MSHookFunction((void *)fopen, MSHake(fopen));
    MSHookFunction((void *)sysctl, MSHake(sysctl));
    MSHookFunction((void *)stat, MSHake(stat));
    MSHookFunction((void *)lstat, MSHake(lstat));
    MSHookFunction((void *)getenv, MSHake(getenv));
    MSHookFunction((void *)isatty, MSHake(isatty));
    MSHookFunction((void *)task_get_exception_ports, MSHake(task_get_exception_ports));
    
    MSHookFunction((void *)_dyld_get_image_name, MSHake(_dyld_get_image_name));
    
    MSHookMessageEx(objc_getClass("NSFileManager"),
                    sel_registerName("fileExistsAtPath:"),
                    (IMP)$NSFileManager$fileExistsAtPath$,
                    (IMP *)&_NSFileManager$fileExistsAtPath$);
    
    MSHookMessageEx(objc_getClass("NSFileManager"),
                    sel_registerName("contentsOfDirectoryAtPath:error:"),
                    (IMP)$NSFileManager$contentsOfDirectoryAtPath$error$,
                    (IMP *)&_NSFileManager$contentsOfDirectoryAtPath$error$);
    MSHookMessageEx(objc_getClass("NSFileManager"),
                    sel_registerName("subpathsOfDirectoryAtPath:error:"),
                    (IMP)$NSFileManager$subpathsOfDirectoryAtPath$error$,
                    (IMP *)&_NSFileManager$subpathsOfDirectoryAtPath$error$);
    MSHookMessageEx(objc_getClass("NSFileManager"),
                    sel_registerName("fileExistsAtPath:isDirectory:"),
                    (IMP)$NSFileManager$fileExistsAtPath$isDirectory$,
                    (IMP *)&_NSFileManager$fileExistsAtPath$isDirectory$);
    MSHookMessageEx(objc_getClass("UIApplication"),
                    sel_registerName("canOpenURL:"),
                    (IMP)$UIApplication$canOpenURL$,
                    (IMP *)&_UIApplication$canOpenURL$);
    
    //    CHLoadClass(NSFileManager);
    //    CHHook1(NSFileManager, fileExistsAtPath);
    //    CHHook2(NSFileManager, contentsOfDirectoryAtPath, error);
    //    CHHook2(NSFileManager, subpathsOfDirectoryAtPath, error);
    //    CHHook2(NSFileManager, fileExistsAtPath, isDirectory);
}
