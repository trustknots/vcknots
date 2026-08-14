const baseUrl = 'https://localhost.emobix.co.uk:8443'

async function main() {
  const response = await fetch(baseUrl, {
    redirect: 'manual',
  })

  console.log('status:', response.status)
  console.log('location:', response.headers.get('location'))

  if (response.status >= 500) {
    throw new Error(`Conformance Suite is not available: ${response.status}`)
  }

  console.log('OIDF Conformance Suite is reachable.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
