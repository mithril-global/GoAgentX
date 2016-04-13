//
//  GAServiceProfile.h
//  GoAgentX
//
//  Created by Xu Jiwei on 13-5-13.
//  Copyright (c) 2013年 xujiwei.com. All rights reserved.
//

#import <Foundation/Foundation.h>

@class GAService;

@interface GAServiceProfile : NSObject

+ (instancetype)profileWithFile:(NSString *)path;

- (id)initWithName:(NSString *)name service:(Class)serviceClass;

- (id)initWithName:(NSString *)name serviceIdentifier:(NSString *)service;

- (id)copyAsNewProfile;

- (id)configValueForKey:(NSString *)key;

- (BOOL)boolConfigValueForKey:(NSString *)key;

- (NSInteger)integerConfigValueForKey:(NSString *)key;

- (NSString *)stringConfigValueForKey:(NSString *)key;

- (NSData *)dataConfigValueForKey:(NSString *)key;

- (NSDictionary *)dictionaryConfigValueForKey:(NSString *)key;

- (NSArray *)arrayConfigValueForKey:(NSString *)key;

- (void)setConfigValue:(id)val forKey:(NSString *)key;

- (void)removeConfigValueForKey:(NSString *)key;

- (void)saveToFile;

@property (nonatomic, strong)   NSUUID          *uuid;
@property (nonatomic, strong)   NSString        *name;
@property (nonatomic, readonly) NSString        *identifier;
@property (nonatomic, readonly) NSString        *serviceIdentifier;
@property (nonatomic, strong)   NSString        *path;
@property (nonatomic, readonly) NSMutableDictionary *data;
@property (nonatomic, assign)   BOOL            isBuildInProfile;
@property (nonatomic, assign)   BOOL            isEditable;
@property (nonatomic, strong)   GAService       *service;
@property (nonatomic, strong)   NSArray         *helpURLs;
@property (nonatomic, strong)   NSBundle        *containerBundle;

@end
