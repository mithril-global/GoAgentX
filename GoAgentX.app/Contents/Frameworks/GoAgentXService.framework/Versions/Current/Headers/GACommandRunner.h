//
//  GACommandRunner.h
//  GoAgentX
//
//  Created by Xu Jiwei on 12-2-13.
//  Copyright (c) 2012年 xujiwei.com. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^GACommandRunnerTerminationHandler)(NSTask *task);

@interface GACommandRunner : NSObject {
}

+ (NSString *)runCommandSync:(NSString *)path
            currentDirectory:(NSString *)curDir
                   arguments:(NSArray *)arguments
                   inputText:(NSString *)inputText;

- (BOOL)isTaskRunning;
- (void)terminateTask;
- (int)processId;

- (void)run;

- (void)waitTaskUntilDone:(id)sender;

- (void)runCommand:(NSString *)path
  currentDirectory:(NSString *)curDir
         arguments:(NSArray *)arguments
         inputText:(NSString *)text
    outputTextView:(NSTextView *)textView
terminationHandler:(GACommandRunnerTerminationHandler)terminationHandler;

- (void)appendDataOfString:(NSData *)data;


@property (nonatomic, readonly) NSMutableAttributedString   *outputStorage;
@property (nonatomic, strong)   NSString        *commandPath;
@property (nonatomic, strong)   NSString        *workDirectory;
@property (nonatomic, strong)   NSArray         *arguments;
@property (nonatomic, strong)   NSDictionary    *environment;
@property (nonatomic, strong)   NSString        *inputText;
@property (nonatomic, strong)   NSTextView      *outputTextView;
@property (nonatomic, copy)     GACommandRunnerTerminationHandler   terminationHandler;

@end
