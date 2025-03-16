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
    ssize_t retval = 0;
    int total_num_bytes;
    int read_off = *f_pos;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    int node_offset = 0;
    int num_in_node = 0;
    int final_num_bytes = 0;
    int idx;
    int num_nodes;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    mutex_lock(dev->lock);

    if(dev->buf->full){
        num_nodes = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else{
        num_nodes = (dev->buf->in_offs - dev->buf->out_offs);
    }
    
    total_num_bytes = 0;

    for (int i = 0; i < num_nodes; i++) {
        idx = (dev->buf->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        total_num_bytes += dev->buf->entry[idx].size;
    }

    //end of file
    if (read_off >= total_num_bytes) {
        mutex_unlock(dev->lock);
        return 0;
    }

    while (count > 0 && (entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->buf, read_off, (size_t *)&node_offset)) != NULL) {

        num_in_node = entry->size - node_offset;

        if(count < num_in_node){
            num_in_node = count;
        }

        if (copy_to_user(buf, entry->buffptr + node_offset, num_in_node) != 0){
            mutex_unlock(dev->lock);
            return -EFAULT;
        }

        buf += num_in_node;
        count -= num_in_node;
        read_off += num_in_node;
        final_num_bytes += num_in_node;
    }

    *f_pos = read_off;

    mutex_unlock(dev->lock);

    return final_num_bytes;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    char *temp_buffer = NULL;
    int accum_len;
    char *newline = NULL;
    int node_offset = 0;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    temp_buffer = kmalloc(count, GFP_KERNEL);

    if(temp_buffer == NULL){
        return -ENOMEM;
    }
    if(copy_from_user(temp_buffer, buf, count)) {
        kfree(temp_buffer);
        return -EFAULT;
    }

    mutex_lock(dev->lock);

    accum_len = dev->ent_size + count;
    newline = kmalloc(accum_len, GFP_KERNEL);
    if(newline == NULL){
        kfree(temp_buffer);
        mutex_unlock(dev->lock);
        return -ENOMEM;
    }
    if(dev->ent){
        memcpy(newline, dev->ent, dev->ent_size);
        kfree(dev->ent);
    }

    memcpy(newline + dev->ent_size, temp_buffer, count);
    kfree(temp_buffer);

    dev->ent = newline;
    dev->ent_size = accum_len;

    while((newline = memchr(dev->ent + node_offset, '\n', dev->ent_size - node_offset)) != NULL){

        int tot_len = newline - (dev->ent + node_offset) + 1;
        char *tmp_buf = kmalloc(tot_len, GFP_KERNEL);
        if(tmp_buf == NULL){
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }
        memcpy(tmp_buf, dev->ent + node_offset, tot_len);
        struct aesd_buffer_entry new_node;
        new_node.buffptr = tmp_buf;
        new_node.size = tot_len;

        const char *prev_line = aesd_circular_buffer_add_entry(dev->buf, &new_node);

        if(prev_line != NULL){
            kfree(prev_line);
        }

        node_offset += tot_len;
    }

    if(node_offset < dev->ent_size) {
        int num_bytes_in_node = dev->ent_size - node_offset;

        char *temp_buf = kmalloc(num_bytes_in_node, GFP_KERNEL);

        if(temp_buf == NULL){
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }
        memcpy(temp_buf, dev->ent + node_offset, num_bytes_in_node);
        kfree(dev->ent);
        dev->ent = temp_buf;
        dev->ent_size = num_bytes_in_node;
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

    aesd_device.lock = kmalloc(sizeof(struct mutex), GFP_KERNEL);

	if (aesd_device.lock == NULL) {
    	return -ENOMEM;
    }

    mutex_init(aesd_device.lock);

    aesd_device.buf = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);

    if (aesd_device.buf == NULL) {

        unregister_chrdev_region(dev, 1);
        return -ENOMEM;

    }

    aesd_circular_buffer_init(aesd_device.buf);

    aesd_device.ent = NULL;
    aesd_device.ent_size = 0;

    aesd_device.cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);

    if (aesd_device.cdev == NULL) {

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

    kfree(aesd_device.lock);

    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {

        if (aesd_device.buf->entry[i].buffptr) {

            kfree(aesd_device.buf->entry[i].buffptr);
            aesd_device.buf->entry[i].buffptr = NULL;
            aesd_device.buf->entry[i].size = 0;

        }
    }

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