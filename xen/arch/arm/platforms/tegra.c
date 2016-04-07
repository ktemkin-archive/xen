/*
 * xen/arch/arm/platforms/tegra.c
 *
 * NVIDIA Tegra specific settings
 *
 * Ian Campbell; Copyright (c) 2014 Citrix Systems
 * Kyle Temkin; Copyright (c) 2016 Assured Information Security, Inc.
 * Chris Patterson; Copyright (c) 2016 Assured Information Security, Inc.
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
#include <xen/sched.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/gic.h>

#define   ICTLR_BASE            0x60004000
#define   ICTLR_SIZE            0x00000100
#define   ICTLR_COUNT           6

#define   TEGRA_RESET_BASE      0x7000e400
#define   TEGRA_RESET_SIZE      4

#define   ICTLR_CPU_IER         0x20
#define   ICTLR_CPU_IER_SET     0x24
#define   ICTLR_CPU_IER_CLR     0x28
#define   ICTLR_CPU_IEP_CLASS   0x2C

#define   ICTLR_COP_IER         0x30
#define   ICTLR_COP_IER_SET     0x34
#define   ICTLR_COP_IER_CLR     0x38
#define   ICTLR_COP_IEP_CLASS   0x3c


/*
 * List of legacy interrupt controller's that can be used to route
 * Tegra interrupts.
 */
static const char * const tegra_interrupt_compat[] __initconst =
{
    "nvidia,tegra210-ictlr"
};

static bool_t tegra_irq_belongs_to_icltr(struct dt_raw_irq * rirq)  {
    int i;

    for (i = 0; i < ARRAY_SIZE(tegra_interrupt_compat); i++) 
    {
        if ( dt_device_is_compatible(rirq->controller, tegra_interrupt_compat[i]) )
            return true;
    }

    return false;
}

static bool_t tegra_irq_is_routable(struct dt_raw_irq * rirq)
{
    /* Always allow GIC interrupts through. */
    if ( rirq->controller == dt_interrupt_controller )
        return true;

    /* Allow legacy IC interrutps to be routable. */
    if ( tegra_irq_belongs_to_icltr(rirq) )
        return true;

    return false;
}

static int tegra_irq_for_device(const struct dt_device_node *device, int index)
{
    struct dt_raw_irq raw;
    struct dt_irq dt_irq;
    int res;

    res = dt_device_get_raw_irq(device, index, &raw);
    if ( res )
        return -ENODEV;

    /*
     * The translation function for the Tegra icltr happens to match the
     * translation function for the normal GIC, so we'll use that in either
     * case.
     */
    res = dt_irq_xlate(raw.specifier, raw.size, &dt_irq.irq, &dt_irq.type);
    if ( res )
        return -ENODEV;

    if ( irq_set_type(dt_irq.irq, dt_irq.type) )
        return -ENODEV;

    return dt_irq.irq;
}


static void tegra_reset(void)
{
    void __iomem *addr;
    u32 val;

    addr = ioremap_nocache(TEGRA_RESET_BASE, TEGRA_RESET_SIZE);
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

static int tegra_initialize_legacy_interrupt_controller(void)
{
    int i;
    void __iomem *ictlr = ioremap_nocache(ICTLR_BASE, ICTLR_SIZE * ICTLR_COUNT);

    if ( !ictlr )
        panic("Failed to map legacy interrupt controller!\n");

    /* Initialize each of the legacy interrupt controllers. */
    for (i = 0; i < ICTLR_COUNT; i++) 
    {
        void __iomem *ictlr_n = ictlr + ICTLR_SIZE * i;

        /* Clear the interrupt enables for every interrupt. */
        writel(~0, ictlr_n + ICTLR_CPU_IER_CLR);

        /*
         * Mark all of our interrupts as normal ARM interrupts (as opposed
         * to Fast Interrupts.)
         */
        writel(0, ictlr_n + ICTLR_CPU_IEP_CLASS);
    }

    iounmap(ictlr);
    return 0;
}



static int tegra_init(void)
{
    return tegra_initialize_legacy_interrupt_controller();
}

static const char * const tegra_dt_compat[] __initconst =
{
    "nvidia,tegra210",
    NULL
};

PLATFORM_START(tegra, "TEGRA")
    .compatible = tegra_dt_compat,
    .init = tegra_init,
    .reset = tegra_reset,
    .irq_is_routable = tegra_irq_is_routable,
    .irq_for_device = tegra_irq_for_device,
PLATFORM_END
