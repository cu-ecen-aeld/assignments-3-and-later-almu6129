#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#define AESD_DEBUG 1  

#undef PDEBUG         
#ifdef AESD_DEBUG
#  ifdef __KERNEL__

#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
   
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) 
#endif

struct aesd_dev
{
    struct aesd_circular_buffer *buf;   
    struct mutex *lock;                  
    char *ent;                   
    size_t ent_size;               
    struct cdev *cdev;    
};


#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */