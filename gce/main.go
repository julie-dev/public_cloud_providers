package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const (
	providerName            = "gce"
	DefaultConfigPath       = "./config.json"
	DefaultInstanceSpecPath = "./instance.json"
)

type Opts struct {
	GCEConfigPath       string
	GCEInstanceSpecPath string
}

type GCEInstanceSpecification struct {
	Kind         string `json:"kind"`
	InstanceName string `json:"instance_name"`
	MachineType  string `json:"machine_type"`
	DiskName     string `json:"disk_name"`
	ImageURL     string `json:"image_url"`
	Network      string `json:"network",omitempty`
}

type GCEConfig struct {
	Kind           string `json:"kind"`
	ProjectID      string `json:"project_id"`
	CredentialFile string `json:"credential_file",omitempty`
	Zone           string `json:"zone",omitempty`
}

func main() {
	ctx := context.Background()

	var opts Opts
	setDefaultOpts(&opts)

	cmd := NewCommand(ctx, filepath.Base(os.Args[0]), &opts)
	if err := cmd.Execute(); err != nil && errors.Cause(err) != context.Canceled {
		log.Fatal(err)
	}

	return
}

func init() {
}

func setDefaultOpts(opts *Opts) {
	if opts.GCEConfigPath == "" {
		opts.GCEConfigPath = DefaultConfigPath
	}

	if opts.GCEInstanceSpecPath == "" {
		opts.GCEInstanceSpecPath = DefaultInstanceSpecPath
	}
}

func NewCommand(ctx context.Context, name string, opts *Opts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   name,
		Short: name + " can handle resources of public cloud using open api",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(ctx, opts)
		},
	}

	setFlags(cmd.Flags(), opts)

	return cmd
}

func setFlags(flags *pflag.FlagSet, opts *Opts) {
	flags.StringVar(&opts.GCEConfigPath, "config", opts.GCEConfigPath, "A file describing GCE authentication information in JSON format")
	flags.StringVar(&opts.GCEInstanceSpecPath, "instance", opts.GCEInstanceSpecPath, "A file describing GCE instance spec in JSON format")
}

func Run(ctx context.Context, opts *Opts) error {
	config, err := loadConfig(opts.GCEConfigPath, providerName)
	if err != nil {
		log.Fatal(err)
	}

	svc, err := ConnectProvider(ctx, &config)
	if err != nil {
		log.Fatal(err)
	}

	err = CreateInstance(ctx, svc, opts, &config)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func ConnectProvider(ctx context.Context, config *GCEConfig) (svc *compute.Service, err error) {
	svc, err = compute.NewService(ctx, option.WithCredentialsFile(config.CredentialFile))
	if err != nil {
		return nil, err
	}

	return svc, nil
}

func CreateInstance(ctx context.Context, svc *compute.Service, opts *Opts, config *GCEConfig) error {
	spec, err := loadInstanceSpec(opts.GCEInstanceSpecPath, providerName)
	if err != nil {
		log.Fatal(err)
	}

	instance := &compute.Instance{
		Name:        spec.InstanceName,
		Description: "compute sample instance",
		MachineType: "/zones/" + config.Zone + "/machineTypes/" + spec.MachineType,
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				DeviceName: spec.InstanceName,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    spec.DiskName,
					SourceImage: spec.ImageURL,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					{
						Type: "ONE_TO_ONE_NAT",
						Name: "External NAT",
					},
				},
				Network: "/global/networks/default",
			},
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email: "default",
				Scopes: []string{
					compute.DevstorageFullControlScope,
					compute.ComputeScope,
				},
			},
		},
	}

	resp, err := svc.Instances.Insert(config.ProjectID, config.Zone, instance).Context(ctx).Do()
	if err != nil {
		log.Fatal(err)
	}

	if resp.HTTPStatusCode != http.StatusOK {
		return fmt.Errorf("Failed %#v\n", resp)
	}

	fmt.Printf("Success %#v\n", resp)
	return nil
}

func loadInstanceSpec(specFile string, provider string) (spec GCEInstanceSpecification, err error) {
	data, err := ioutil.ReadFile(specFile)
	if err != nil {
		return spec, err
	}

	specMap := map[string]GCEInstanceSpecification{}
	err = json.Unmarshal(data, &specMap)
	if err != nil {
		return spec, err
	}

	if _, exist := specMap["instance"]; exist {
		spec = specMap["instance"]
		if spec.Kind != provider {
			return spec, fmt.Errorf("Provider does not match")
		}
	}

	return spec, nil
}

func loadConfig(configFile string, provider string) (config GCEConfig, err error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return config, err
	}

	configMap := map[string]GCEConfig{}
	err = json.Unmarshal(data, &configMap)
	if err != nil {
		return config, err
	}

	if _, exist := configMap["provider"]; exist {
		config = configMap["provider"]
		if config.Kind != provider {
			return config, fmt.Errorf("Provider does not match")
		}
	}

	return config, nil
}
