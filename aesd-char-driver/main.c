#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> 
#include "aesdchar.h"
#include "aesd-circular-buffer.h"

int aesd_major =   0;
int aesd_minor =   0;

MODULE_AUTHOR("Alex Mueller");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = &aesd_device;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    size_t num_bytes_in_buffer = 0;
    size_t new_fpos = *f_pos;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t spot_in_node = 0;
    size_t avail_in_node_rem = 0;
    size_t final_copy_num = 0;
    size_t num_actual_copied = 0;
    int how_many_nodes;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    mutex_lock(dev->lock);

    how_many_nodes = dev->buf->full ? AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED :
                        (dev->buf->in_offs - dev->buf->out_offs);

    for(int i = 0; i < how_many_nodes; i++){
        int pos = (dev->buf->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        num_bytes_in_buffer += dev->buf->entry[pos].size;
    }

    if(new_fpos >= num_bytes_in_buffer){
        mutex_unlock(dev->lock);
        return 0;
    }

    while(count > 0 && (entry = aesd_circular_buffer_find_spot_in_node_for_fpos(dev->buf, new_fpos, &spot_in_node)) != NULL){
        avail_in_node_rem = entry->size - spot_in_node;
        final_copy_num = (count < avail_in_node_rem) ? count : avail_in_node_rem;
        if(copy_to_user(buf, entry->buffptr + spot_in_node, final_copy_num) != 0){
            mutex_unlock(dev->lock);
            return -EFAULT;
        }
        buf += final_copy_num;
        count -= final_copy_num;
        new_fpos += final_copy_num;
        num_actual_copied += final_copy_num;
    }
    *f_pos = new_fpos;
    mutex_unlock(dev->lock);
    return num_actual_copied;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *kern_buf = NULL;
    char *new_cmd = NULL;
    size_t total_len;
    char *newline_ptr = NULL;
    size_t write_offset = 0;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    kern_buf = kmalloc(count, GFP_KERNEL);
    if (!kern_buf)
        return -ENOMEM;
    if (copy_from_user(kern_buf, buf, count)) {
        kfree(kern_buf);
        return -EFAULT;
    }

    mutex_lock(dev->lock);

    total_len = dev->ent_size + count;
    new_cmd = kmalloc(total_len, GFP_KERNEL);
    if(new_cmd == NULL){
        kfree(kern_buf);
        mutex_unlock(dev->lock);
        return -ENOMEM;
    }
    if(dev->ent){
        memcpy(new_cmd, dev->ent, dev->ent_size);
        kfree(dev->ent);
    }
    memcpy(new_cmd + dev->ent_size, kern_buf, count);
    kfree(kern_buf);
    dev->ent = new_cmd;
    dev->ent_size = total_len;

    while((newline_ptr = memchr(dev->ent + write_offset, '\n', dev->ent_size - write_offset)) != NULL){
        size_t cmd_length = newline_ptr - (dev->ent + write_offset) + 1;
        char *cmd_buf = kmalloc(cmd_length, GFP_KERNEL);
        if (!cmd_buf) {
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }
        memcpy(cmd_buf, dev->ent + write_offset, cmd_length);


        struct aesd_buffer_entry new_entry;
        new_entry.buffptr = cmd_buf;
        new_entry.size = cmd_length;

        const char *old_cmd = aesd_circular_buffer_add_entry(dev->buf, &new_entry);
        if(old_cmd) kfree(old_cmd);

        write_offset += cmd_length;
    }


    if (write_offset < dev->ent_size) {
        size_t leftover = dev->ent_size - write_offset;
        char *temp_buf = kmalloc(leftover, GFP_KERNEL);
        if(temp_buf == NULL){
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }
        memcpy(temp_buf, dev->ent + write_offset, leftover);
        kfree(dev->ent);
        dev->ent = temp_buf;
        dev->ent_size = leftover;
    }else{
        kfree(dev->ent);
        dev->ent = NULL;
        dev->ent_size = 0;
    }
    mutex_unlock(dev->lock);

    return count;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(dev->cdev, &aesd_fops);
    dev->cdev->owner = THIS_MODULE;
    dev->cdev->ops = &aesd_fops;
    err = cdev_add(dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    // Initialize the AESD specific portion of the device
    aesd_device.lock = kmalloc(sizeof(struct mutex), GFP_KERNEL);
	if (!aesd_device.lock) {
    	return -ENOMEM;
    }
    mutex_init(aesd_device.lock);
    aesd_device.buf = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if (!aesd_device.buf) {
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    aesd_circular_buffer_init(aesd_device.buf);
    aesd_device.ent = NULL;
    aesd_device.ent_size = 0;

    aesd_device.cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);
    if (!aesd_device.cdev) {
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(aesd_device.cdev);

    // Cleanup AESD specific poritions - circular buffer and pending buffer
    kfree(aesd_device.lock);
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        if (aesd_device.buf->entry[i].buffptr) {
            kfree(aesd_device.buf->entry[i].buffptr);
            aesd_device.buf->entry[i].buffptr = NULL;
            aesd_device.buf->entry[i].size = 0;
        }
    }
    // Free any pending buffer
    if (aesd_device.ent) {
        kfree(aesd_device.ent);
        aesd_device.ent = NULL;
        aesd_device.ent_size = 0;
    }
    kfree(aesd_device.buf);
    kfree(aesd_device.cdev);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);