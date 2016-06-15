static void devm_iounmap_resource(struct device *d, struct resource *r,
							void __iomem *addr)
{
	devm_iounmap(d, addr);
	devm_release_mem_region(d, r->start, resource_size(r));
}

