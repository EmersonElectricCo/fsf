rule ft_macho
{
   meta:
      author = "Jamie Ford"
      company = "BroEZ"
      lastmod = "September 5 2016"
      desc = "Signature to trigger on mach-o file format."

   strings:
      $MH_CIGAM_64 = { CF FA ED FE }
      $MH_MAGIC_64 = { FE ED FA CF }
      $MH_MAGIC_32 = { FE ED FA CE }
      $MH_CIGAM_32 = { CE FA ED FE }
      $FAT_MAGIC = { CA FE BA BE }
      $FAT_CIGAM = { BE BA FE CA }

   condition:
      ($MH_CIGAM_64 at 0) or ($MH_MAGIC_64 at 0) or ($MH_CIGAM_32 at 0) or ($MH_MAGIC_32 at 0) or ($FAT_MAGIC at 0) or ($FAT_CIGAM at 0)
}