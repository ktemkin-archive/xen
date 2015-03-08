/*
 * xen/arch/arm/platforms/tegra.c
 *
 * Nvidia Tegra specific settings
 *
 * Ian Campbell
 * Copyright (c) 2014 Citrix Systems
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <asm/platform.h>
#include <xen/stdbool.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/gic.h>

#define ICTLR_BASE 0x60004000
#define ICTLR_SIZE 0x00001000

#define ICTLR_CPU_IEP_VFIQ	0x08
#define ICTLR_CPU_IEP_FIR	0x14
#define ICTLR_CPU_IEP_FIR_SET	0x18
#define ICTLR_CPU_IEP_FIR_CLR	0x1c

#define ICTLR_CPU_IER		0x20
#define ICTLR_CPU_IER_SET	0x24
#define ICTLR_CPU_IER_CLR	0x28
#define ICTLR_CPU_IEP_CLASS	0x2C

#define ICTLR_COP_IER		0x30
#define ICTLR_COP_IER_SET	0x34
#define ICTLR_COP_IER_CLR	0x38
#define ICTLR_COP_IEP_CLASS	0x3c

static void __iomem *ictlr;

struct {
    uint32_t allow_dom0;
} ictlr_info[5] = {
    [0] = { 0x0 },
    [1] = { 0x0 },
    [2] = { 0x0 },
    [3] = { 0x0 },
    [4] = { 0x0 },
};

static int ictlr_read(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    uint32_t offs = info->gpa - ICTLR_BASE;
    int ctlrnr = offs >> 8;
    int reg = offs & 0xff;

    uint32_t val;

    if ( offs > 0x4ff )
    {
        printk("UNHANDLED READ FROM %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }
    if ( offs & 0x3 )
    {
        printk("MISALIGNED READ FROM %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }
    if ( dabt.size != DABT_WORD )
    {
        printk("NON-WORD READ FROM %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }

    switch ( reg ) {
    /* Read only */
    case 0x00 ... 0x14:
    case 0x20:
    case 0x30:
    case 0x60 ... 0x68:
    case 0x78 ... 0x80:
    case 0x90 ... 0x98:
    /* Read/write */
    case 0x2C:
    case 0x3C:
    case 0x74:
    case 0x8C:
    case 0xA4:
        val = readl(ictlr + offs);
        *r = val & ictlr_info[ctlrnr].allow_dom0;
        if ( val != *r )
            printk("TEGRA: ICTLR%d READ %x INTO r%d=%08"PRIregister" (%08"PRIregister")\n",
                   ctlrnr+1, reg, dabt.reg, *r, val);
        return 1;
    /* Write only */
    case 0x18 ... 0x1c:
    case 0x24 ... 0x28:
    case 0x34 ... 0x38:
    case 0x6C ... 0x70:
    case 0x84 ... 0x88:
    case 0x9C ... 0xA0:
        printk("READ FROM WO %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
        break;
    case 0xa8 ... 0xff:
        printk("READ FROM NON-EXISTENT %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
        break;
    default:
        BUG();
    }
}

static int ictlr_write(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    uint32_t offs = info->gpa - ICTLR_BASE;
    int ctlrnr = offs >> 8;
    int reg = offs & 0xff;

    uint32_t val = *r;

    if ( offs > 0x4ff )
    {
        printk("UNHANDLED WRITE TO %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }
    if ( offs & 0x3 )
    {
        printk("MISALIGNED WRITE TO %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }
    if ( dabt.size != DABT_WORD )
    {
        printk("NON-WORD WRITE TO %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    }

    val &= ictlr_info[ctlrnr].allow_dom0;

    switch ( reg ) {
    /* Read only */
    case 0x00 ... 0x14:
    case 0x20:
    case 0x30:
    case 0x60 ... 0x68:
    case 0x78 ... 0x80:
    case 0x90 ... 0x98:
        printk("WRITE TO RO %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
    /* Read/write */
    case 0x2C:
    case 0x3C:
    case 0x74:
    case 0x8C:
    case 0xA4:
    /* Write only */
    case 0x18 ... 0x1c:
    case 0x24 ... 0x28:
    case 0x34 ... 0x38:
    case 0x6C ... 0x70:
    case 0x84 ... 0x88:
    case 0x9C ... 0xA0:
        if ( val != *r )
            printk("TEGRA: ICTLR%d WRITE r%d=%08"PRIregister" (%08"PRIregister") INTO %x\n",
                   ctlrnr+1, dabt.reg, val, *r, reg);
        writel(val, ictlr + offs);
        return 1;
    case 0xa8 ... 0xff:
        printk("READ FROM NON-EXISTENT %"PRIpaddr"\n", info->gpa);
        domain_crash_synchronous();
        break;
    default:
        BUG();
    }
}

static struct mmio_handler_ops tegra_mmio_ictlr = {
    .read_handler = ictlr_read,
    .write_handler = ictlr_write,
};

static void tegra_route_irq_to_guest(struct domain *d, struct irq_desc *desc)
{
    int irq = desc->irq;
    int ctlrnr;
    uint32_t mask;

    if ( irq < NR_LOCAL_IRQS )
        return;

    if ( d->domain_id )
        return;

    ctlrnr = ( irq - NR_LOCAL_IRQS ) / 32;
    mask = BIT((irq - NR_LOCAL_IRQS) % 32);
    printk("TEGRA: Routing IRQ%d to dom0, ICTLR%d, mask %#08x\n",
           irq, ctlrnr, mask);
    ictlr_info[ctlrnr].allow_dom0 |= mask;
}

static int map_one_mmio(struct domain *d, const char *what,
                         unsigned long start, unsigned long end)
{
    int ret;

    printk("Additional MMIO %lx-%lx (%s)\n",
           start, end, what);
    ret = map_mmio_regions(d, start, end - start + 1, start);
    if ( ret )
        printk("Failed to map %s @ %lx to dom%d\n",
               what, start, d->domain_id);
    return ret;
}

static int map_one_spi(struct domain *d, const char *what,
                       unsigned int spi, unsigned int type)
{
    unsigned int irq;
    int ret;

    irq = spi + 32; /* SPIs start at IRQ 32 */

    ret = irq_set_spi_type(irq, type);
    if ( ret )
    {
        printk("Failed to set the type for IRQ%u\n", irq);
        return ret;
    }

    printk("Additional IRQ %u (%s)\n", irq, what);

    ret = route_irq_to_guest(d, irq, what);
    if ( ret )
        printk("Failed to route %s to dom%d\n", what, d->domain_id);

    return ret;
}

/*
 * Xen does not currently support mapping MMIO regions and interrupt
 * for bus child devices (referenced via the "ranges" and
 * "interrupt-map" properties to domain 0). Instead for now map the
 * necessary resources manually.
 */
static int tegra_specific_mapping(struct domain *d)
{
    int ret;

    ret = map_one_mmio(d, "IRAM", paddr_to_pfn(0x40000000),
                                  paddr_to_pfn(0x40040000));
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "Display A", paddr_to_pfn(0x54200000),
                                       paddr_to_pfn(0x54240000));
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "Display B", paddr_to_pfn(0x54240000),
                                       paddr_to_pfn(0x54280000));
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "EXCEPTION VECTORS", paddr_to_pfn(0x6000f000),
                                               paddr_to_pfn(0x60010000));
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "SYSREG", paddr_to_pfn(0x6000c000),
                                    paddr_to_pfn(0x6000d000));
    if ( ret )
        goto err;

    ret = map_one_mmio(d, "PCI CFG0", paddr_to_pfn(0x01000000),
                                      paddr_to_pfn(0x01001000));
    if ( ret )
        goto err;
    ret = map_one_mmio(d, "PCI CFG1", paddr_to_pfn(0x01001000),
                                      paddr_to_pfn(0x01002000));
    if ( ret )
        goto err;
    ret = map_one_mmio(d, "PCI IO", paddr_to_pfn(0x12000000),
                                    paddr_to_pfn(0x12010000));
    if ( ret )
        goto err;
    ret = map_one_mmio(d, "PCI MEM", paddr_to_pfn(0x13000000),
                                     paddr_to_pfn(0x20000000));
    if ( ret )
        goto err;
    ret = map_one_mmio(d, "PCI MEM (PREFETCH)", paddr_to_pfn(0x20000000),
                                                paddr_to_pfn(0x40000000));
    if ( ret )
        goto err;

    ret = map_one_spi(d, "DISPLAY", 73, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    ret = map_one_spi(d, "DISPLAY B", 74, DT_IRQ_TYPE_LEVEL_HIGH);
    if ( ret )
        goto err;

    register_mmio_handler(d, &tegra_mmio_ictlr, ICTLR_BASE, ICTLR_SIZE);

    ret = 0;
err:
    return ret;
}

static void tegra_reset(void)
{
    void __iomem *addr;
    u32 val;
    addr = ioremap_nocache(0x7000e400, 4);

    if ( !addr )
    {
        printk("Tegra: Unable to map tegra reset address, can not reset...\n");
        return;
    }

    val = readl(addr);
    val |= 0x10;
    writel(val, addr);

    iounmap(addr);
}


static int tegra_init(void)
{
    int i;

    ictlr = ioremap_nocache(ICTLR_BASE, ICTLR_SIZE);
    if ( !ictlr )
        panic("Failed to map intc\n");

    for (i = 0; i < ARRAY_SIZE(ictlr_info); i++) {
        void __iomem *ictlr_n = ictlr + 0x100*i;
        writel(~0, ictlr_n + ICTLR_CPU_IER_CLR);
        writel(0, ictlr_n + ICTLR_CPU_IEP_CLASS);
    }

    return 0;
}

static const char * const tegra_dt_compat[] __initconst =
{
    "nvidia,tegra124",
    NULL
};

static const struct dt_device_match tegra_blacklist_dev[] __initconst =
{
    /*
     * The UARTs share a page which runs the risk of mapping the Xen console
     * UART to dom0, so don't map any of them.
     */
    DT_MATCH_COMPATIBLE("nvidia,tegra20-uart"),
    { /* sentinel */ },
};

PLATFORM_START(tegra, "TEGRA124")
    .compatible = tegra_dt_compat,
    .blacklist_dev = tegra_blacklist_dev,
    .init = tegra_init,
    .reset = tegra_reset,
    .specific_mapping = tegra_specific_mapping,

    .route_irq_to_guest = tegra_route_irq_to_guest,

    .dom0_gnttab_start = 0x68000000,
    .dom0_gnttab_size = 0x20000,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
