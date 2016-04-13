//
//  GAService.h
//  GoAgentX
//
//  Created by Xu Jiwei on 12-4-24.
//  Copyright (c) 2012年 xujiwei.com. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "GAServiceProfile.h"
#import "GACommandRunner.h"

#define GXLocalizedString(key, comment) [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:key table:nil]


extern NSString *GAServiceNeedsPrepareWorkingDirectoryNotification;

extern NSString *GXUseCustomConfigTemplateKey;

extern NSString *GXCustomConfigTemplate;

@class GAService;


//! 服务状态
typedef NS_ENUM(NSInteger, GAServiceState) {
    GAServiceStateNotConfigured,
    GAServiceStateStopped,
    GAServiceStateRunning,
};


//! 代理类型
typedef NS_ENUM(NSInteger, GAProxyType) {
    GAProxyTypeHTTP     = 1 << 0,   // HTTP proxy, with CONNECT command support
    GAProxyTypeSOCKS    = 1 << 1,   // SOCKS proxy
    GAProxyTypeHTTPOnly = 1 << 2,   // HTTP without CONNECT support, only used in goagent
};


@interface GXProxyInfo : NSObject
@property (nonatomic, readonly)   GAProxyType     type;
@property (nonatomic, readonly)   NSInteger       port;
@property (nonatomic, readonly)   NSString        *name;
@property (nonatomic, readonly)   NSString        *serviceName;
@property (nonatomic, readonly)   GAServiceState  serviceState;
@property (nonatomic, readonly)   NSString        *profileIdentifier;
@end


typedef void (^GAServiceStatusChangedHandler)(GAService *service);


@protocol GAService <NSObject>

+ (NSString *)serviceName;

+ (NSBundle *)bundle;

+ (NSString *)bundleIdentifier;

+ (NSString *)bundleVersion;

+ (NSImage *)bundleIcon;

+ (NSDictionary *)profileDefaults;

+ (NSArray *)helpURLs;

- (NSString *)serviceName;

- (NSImage *)bundleIcon;

- (NSString *)bundleIdentifier;

- (NSString *)bundleVersion;

- (NSBundle *)bundle;

- (NSDictionary *)profileDefaults;

- (NSArray *)helpURLs;

- (BOOL)hasHelpURLs;

- (NSArray *)advancedConfigViewNames;

- (void)setupAdvancedConfigViews;

- (void)setNeedsPrepareWorkingDirectory;

- (void)configValueChangedForKey:(NSString *)key;

@end


@interface GAService : NSObject <GAService>

//! 配置文件必须要填写的字段列表
- (NSArray *)requiredConfigKeys;

//! 服务是否已经完成配置，如果只有判断有没有填必须的字段，可以只实现 requiredConfigKeys
- (BOOL)hasConfigured;

//! 是否需要在网络出现问题时停止服务
- (BOOL)shouldStopWhenNetworkDisconnected;

//! 默认配置文件模板
- (NSString *)defaultConfigTemplate;

//! 配置文件模板
- (NSString *)configTemplate;

//! 配置文件在工作目录中的路径
- (NSString *)configPath;

//! 代理端口
- (int)proxyPort;

//! 代理监听地址
- (NSString *)proxyAddressWithHost:(NSString *)host;

//! 代理类型
- (GAProxyType)proxyType;

//! 返回在 PAC 文件中的代理设置，如 PROXY localhost:8080
- (NSString *)proxySettingForPACWithHost:(NSString *)host;

//! 转换配置文件中的值
- (id)transformConfigValue:(id)obj forKey:(NSString *)key;

//! 初始化运行服务的 commander
- (void)setupCommandRunner:(GACommandRunner *)commandRunner;

- (void)refreshServiceState;

//! 服务将要被停止时被调用
- (void)willTerminate;

//! 服务已停止时被调用
- (void)didTerminate;

//! 服务将要启动时被调用
- (void)willStart;

//! 服务启动完成时被调用
- (void)didStart;

//! 批量测试域名的响应时间
- (void)pingHosts:(NSArray *)hosts progress:(void (^)(float progress))progressBlock callback:(void (^)(NSArray *sortedHosts, NSArray *pings))callback;

@property (nonatomic, assign)   BOOL                            manualStopped;
@property (nonatomic, strong)   IBOutlet    NSView              *configView;
@property (nonatomic, strong)   IBOutlet    NSView              *statusView;
@property (nonatomic, readonly) NSString                        *serviceName;
@property (nonatomic, readonly) NSBundle                        *bundle;
@property (nonatomic, readonly) NSString                        *bundleIdentifier;
@property (nonatomic, readonly) NSString                        *bundleVersion;
@property (nonatomic, readonly) NSImage                         *bundleIcon;
@property (nonatomic, assign)   GAServiceProfile                *runningProfile;
@property (nonatomic, readonly) NSDictionary                    *config;
@property (nonatomic, readonly) NSArray                         *helpURLs;
@property (nonatomic, readonly) BOOL                            hasHelpURLs;
@property (nonatomic, strong)   NSString                        *workingDirectoryPath;
@property (nonatomic, readonly) BOOL                            isRunning;
@property (nonatomic, strong)   GACommandRunner                 *commandRunner;
@property (nonatomic, assign)   NSInteger                       retryCount;
@property (nonatomic, assign)   GAServiceState                  serviceState;
@property (nonatomic, strong)   NSScrollView                    *logView;
@property (nonatomic, strong)   NSArray                         *otherProxies;
@property (nonatomic, readonly) GXProxyInfo                     *proxyInfo;

@end
