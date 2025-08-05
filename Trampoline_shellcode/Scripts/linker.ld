SECTIONS
{
	.text :
	{
		*( .text$A )
		*( .text$V )
		*( .text$B )
		*( .text$C )
		*( .text$D )
		*( .text$E )
		*( .rdata* )
	}
}
