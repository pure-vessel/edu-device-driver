#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/cdev.h>

#include <edu.h>

// Use lagacy interrupts flag.
#define EDU_LEGACY_INTERRUPT 0

// Edu prefix for logging.
#define EDU_LOG_PREFIX "edu: "
// Universal kernel log macro.
#define log(level, format, ...) printk(level EDU_LOG_PREFIX format "\n", ##__VA_ARGS__)
// Kernel information log macro.
#define log_info(format, ...)   log(KERN_INFO, format, ##__VA_ARGS__)
// Kernel error log macro.
#define log_error(format, ...)  log(KERN_ERR, format, ##__VA_ARGS__)

#define EDU_IDENT       0x00
#define EDU_IDENT_MASK_MAJOR  0xff000000
#define EDU_IDENT_MASK_MINOR  0x00ff0000
#define EDU_IDENT_SHIFT_MAJOR 24
#define EDU_IDENT_SHIFT_MINOR 16
#define EDU_IDENT_MASK_MAGIC  0x000000ff
#define EDU_IDENT_MAGIC       0xed

#define EDU_XOR         0x04
#define EDU_FACTORIAL   0x08
#define EDU_STATUS      0x20
#define EDU_STATUS_COPMUTING  0x01
#define EDU_STATUS_RAISE_INTR 0x80

#define EDU_INTR_STATUS 0x24
#define EDU_INTR_RAISE  0x60
#define EDU_INTR_ACK    0x64

#define EDU_DMA_SRC     0x80
#define EDU_DMA_DEST    0x88
#define EDU_DMA_CNT     0x90
#define EDU_DMA_CMD     0x98
#define EDU_DMA_CMD_START      0x01
#define EDU_DMA_CMD_DIR_TO_EDU 0x00
#define EDU_DMA_CMD_DIR_TO_RAM 0x02
#define EDU_DMA_CMD_RAISE_INTR 0x04

// Edu device structure.
struct edu_device
{
    // Kernel device information.
    struct pci_dev *pdev;
    // Device "magic memory" pointer.
    void __iomem *map;

    // Character device structure.
    struct cdev cdev;
    // Mutex for locking device operations.
    struct mutex lock;
    // Device openings amount.
    unsigned open_count;
    // Basic devise structure.
    struct device *dev;
};

// Device class structure.
static struct class *edu_class;
// Created devices amount.
static atomic_t n_devices = ATOMIC_INIT(0);

static long edu_do_xor(struct edu_device *edu, unsigned long arg)
{
    struct edu_xor_cmd __user *cmd = (void __user *)(arg);
    u32 val_in, val_out;

    if (get_user(val_in, &cmd->val_in))
        return -EINVAL;

    iowrite32(val_in, edu->map + EDU_XOR);
    val_out = ioread32(edu->map + EDU_XOR);

    if (put_user(val_out, &cmd->val_out))
        return -EINVAL;

    return 0;
}

static long edu_do_factorial(struct edu_device *edu, unsigned long arg)
{
    return -ENXIO;
}

static long edu_do_intr(struct edu_device *edu, unsigned long arg)
{
    struct edu_intr_cmd __user *cmd = (void __user *)(arg);
    u32 val_in;

    if (get_user(val_in, &cmd->val_in))
        return -EINVAL;
    
    iowrite32(val_in, edu->map + EDU_INTR_RAISE);

    return 0;
}



// I/O control.
// file - opened device properties.
// cmd - I/O contril operation type.
// arg - operation argument.
static long edu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct edu_device *edu = file->private_data;

    switch (cmd)
    {
        case EDU_IOCTL_XOR:
            return edu_do_xor(edu, arg);

        case EDU_IOCTL_FACTORIAL:
            return edu_do_factorial(edu, arg);

        case EDU_IOCTL_INTR:
            return edu_do_intr(edu, arg);

        default:
            return -EINVAL;
    }
}

// I/O control.
// inode - device index node.
// file - opened device properties.
static int edu_open(struct inode *inode, struct file *file)
{
    struct edu_device *edu = container_of(inode->i_cdev, struct edu_device, cdev);

    mutex_lock(&edu->lock);

    if (edu->open_count)
    {
        mutex_unlock(&edu->lock);
        return -EBUSY;
    }

    edu->open_count++;
    file->private_data = edu;

    mutex_unlock(&edu->lock);

    return 0;
}

// Close file.
static int edu_release(struct inode *inode, struct file *file)
{
    struct edu_device *edu = file->private_data;

    mutex_lock(&edu->lock);
    edu->open_count--;
    mutex_unlock(&edu->lock);

    return 0;
}

// Character device operations.
static struct file_operations edu_fops =
{
    .owner = THIS_MODULE,
    .open = edu_open,
    .release = edu_release,
    .unlocked_ioctl = edu_ioctl,
    // Easy way to create compatibility between 32- and 64-bit architectures.
    .compat_ioctl = compat_ptr_ioctl,
};

static int edu_create_chardev(struct edu_device *edu)
{
    int rc;
    unsigned n;
    dev_t devt; // Kernel device number representation.
    struct device *dev;

    // Incrementing devices count.
    n = atomic_fetch_add(1, &n_devices);
    // Evaluating device version.
    devt = MKDEV(EDU_MAJOR, n);
    // Setting openengs count as 0.
    edu->open_count = 0;
    // Initializating mutex.
    mutex_init(&edu->lock);
    // Initializating character device structure.
    cdev_init(&edu->cdev, &edu_fops);
    // Seting character device owner.
    edu->cdev.owner = THIS_MODULE; // They say, that SET_MODULE_OWNER is more universal.
    // "Reviving" device.
    rc = cdev_add(&edu->cdev, devt, 1);
    if (rc)
    {
        log_error("%s: failed to add a cdev (rc = %d)", pci_name(edu->pdev), rc);
        return rc;
    }
    // Creating and registering device.
    dev = device_create(edu_class, &edu->pdev->dev, devt, NULL, "edu%u", n);
    if (IS_ERR(dev))
    {
        rc = PTR_ERR(dev);
        log_error("%s: failed to create a device (rc = %d)", pci_name(edu->pdev), rc);
        cdev_del(&edu->cdev);
        return rc;
    }

    edu->dev = dev;
    return 0;
}

static void edu_destroy_chardev(struct edu_device *edu)
{
    device_destroy(edu_class, edu->dev->devt);
    cdev_del(&edu->cdev);
}

// Interruption processing.
// irq - No thoughts about it.
// data - Device data.
static irqreturn_t edu_irq(int irq, void *data)
{
    struct pci_dev *dev = data;
    struct edu_device *edu = pci_get_drvdata(data);
    u32 status;

    status = ioread32(edu->map + EDU_INTR_STATUS);
    if (!status)
        return IRQ_NONE;

    log_info("%s: got interrupted (%x)", pci_name(dev), status);
    // Write that interruption proocessed.
    iowrite32(status, edu->map + EDU_INTR_ACK);

    return IRQ_HANDLED;
}

// Chaecking device version.
static int edu_check_version(struct pci_dev *dev, void __iomem *map)
{
    u32 ident;
    u8 major, minor, magic;

    ident = ioread32(map + EDU_IDENT);
    major = (ident & EDU_IDENT_MASK_MAJOR) >> EDU_IDENT_SHIFT_MAJOR;
    minor = (ident & EDU_IDENT_MASK_MINOR) >> EDU_IDENT_SHIFT_MINOR;
    magic = (ident & EDU_IDENT_MASK_MAGIC);

    if (magic != EDU_IDENT_MAGIC)
    {
        log_error("%s: magic (0x%x) is wrong, aborting", pci_name(dev), magic);
        return -ENODEV;
    }

    if (major != 1)
    {
        log_error("%s: only major version 1 is supported (%d), aborting",
                  pci_name(dev), major);
        return -ENODEV;
    }

    log_info("%s: major %d minor %d", pci_name(dev), major, minor);

    return 0;
}

// Checking if driver could be linked to the device function.
static int edu_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    int rc;
    struct edu_device *edu;

    // Allocationg memory for device.
    edu = devm_kzalloc(&dev->dev, sizeof(struct edu_device), GFP_KERNEL);
    if (!edu)
        return -ENODEV;

    edu->pdev = dev;
    pci_set_drvdata(dev, edu);

    // Initializing device.
    rc = pci_enable_device(dev);
    if (rc)
        goto err_free_edu;

    // Enabling bus-mastering ("magic memory" if I understand right).
    pci_set_master(dev);

    // Reserve device BARs.
    rc = pci_request_region(dev, 0, "edu-bar0");
    if (rc)
    {
        log_error("%s: failed to request BAR0 (rc = %d)", pci_name(dev), rc);
        goto err_disable_device;
    }

    // Receiving BAR "magic memory".
    edu->map = pci_iomap(dev, 0, 0);
    if (!edu->map)
    {
        log_error("%s: failed to map BAR0", pci_name(dev));
        rc = -ENODEV;
        goto err_free_region;
    }

    // Checking for right device version.
    rc = edu_check_version(dev, edu->map);
    if (rc)
        //goto err_free_region;
        goto err_iounmap;

    // Enabling multiple interrupt requests.
#if EDU_LEGACY_INTERRUPT
    rc = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_LEGACY);
#else
    rc = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI);
#endif 
    if (rc < 0)
    {
        log_error("%s: failed to allocate IRQ (rc = %d)", pci_name(dev), rc);
        goto err_iounmap;
    }

    // Setting interruptions handler.
#if EDU_LEGACY_INTERRUPT
    rc = request_irq(pci_irq_vector(dev, 0), edu_irq, IRQF_SHARED, "edu-irq", dev);
#else
    rc = request_irq(pci_irq_vector(dev, 0), edu_irq, 0, "edu-irq", dev);
#endif
    if (rc)
    {
        log_error("%s: failed to request IRQ (rc = %d)", pci_name(dev), rc);
        goto err_free_vectors;
    }

    // Creating character device.
    rc = edu_create_chardev(edu);
    if (rc)
        goto err_free_irq;

    return 0;

err_free_irq:
    free_irq(pci_irq_vector(dev, 0), dev);
err_free_vectors:
    pci_free_irq_vectors(dev);
err_free_region:
    pci_release_region(dev, 0);
err_iounmap:
    pci_iounmap(dev, edu->map);
err_disable_device:
    pci_disable_device(dev);
err_free_edu:
    kfree(edu);

    return rc;
}

static void edu_remove(struct pci_dev *dev)
{
    struct edu_device *edu = pci_get_drvdata(dev);

    edu_destroy_chardev(edu);
    free_irq(pci_irq_vector(dev, 0), dev);
    pci_free_irq_vectors(dev);
    pci_iounmap(dev, edu->map);
    pci_release_region(dev, 0);
    pci_disable_device(dev);
    devm_kfree(&dev->dev, edu);
}

static struct pci_device_id edu_id_table[] =
{
    // Numbers from specification.
    { PCI_DEVICE(0x1234, 0x11e8) },
    { 0 }
};

static struct pci_driver edu_driver =
{
    .name = "edu",
    .id_table = edu_id_table,
    .probe = edu_probe,
    .remove = edu_remove,
};

static int __init edu_init(void)
{
    int rc;

    // Creating device class structure.
    edu_class = class_create(THIS_MODULE, "edu");
    if (IS_ERR(edu_class))
    {
        log_error("failed to create 'edu' class");
        return PTR_ERR(edu_class);
    }

    // Adding new driver to the registered drivers list.
    rc = pci_register_driver(&edu_driver);
    if (rc)
    {
        log_error("failed to register PCI device (rc = %d)", rc);
        class_destroy(edu_class);
        return rc;
    }

    return 0;
}

static void __exit edu_exit(void)
{
    pci_unregister_driver(&edu_driver);
    class_destroy(edu_class);
}

module_init(edu_init);
module_exit(edu_exit);

MODULE_AUTHOR("Ivanov Timophey");
MODULE_DESCRIPTION("QEMU's 'edu' device driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("2");


// insmod, dmesg, rmmod