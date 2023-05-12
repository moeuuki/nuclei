package manager

import (
	"context"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/plugins/proto"
)

// getHelperFunctionInfo returns the helper function plugins info
func (m *Manager) getHelperFunctionInfo(plugin *Plugin, newRuntime proto.WazeroNewRuntime) (*proto.HelperFunctionInfo, error) {
	helperFunctions, err := proto.NewHelperFunctionPlugin(context.Background(), proto.WazeroRuntime(newRuntime))
	if err != nil {
		return nil, errors.Wrap(err, "could not create helper function plugin")
	}

	helper, err := helperFunctions.Load(context.Background(), plugin.Path)
	if err != nil {
		return nil, errors.Errorf("could not load helper function plugin %s: %s", plugin.Name, err)
	}
	defer helper.Close(context.Background())

	info, err := helper.Info(context.Background(), &proto.Empty{})
	if err != nil {
		return nil, errors.Errorf("could not get info for helper function plugin %s: %s", plugin.Name, err)
	}
	return info, nil
}

// initializeHelperFunctionPlugin initializes a helper function plugin
func (m *Manager) initializeHelperFunctionPlugin(plugin *Plugin, ctx *initializeContext) error {
	helper, err := ctx.helperFunctions.Load(context.Background(), plugin.Path)
	if err != nil {
		return errors.Errorf("could not load helper function plugin %s: %s", plugin.Name, err)
	}
	defer helper.Close(context.Background())

	info, err := helper.Info(context.Background(), &proto.Empty{})
	if err != nil {
		return errors.Errorf("could not get info for helper function plugin %s: %s", plugin.Name, err)
	}

	for _, item := range info.Items {
		item := item

		if len(item.Signatures) > 0 {
			dsl.MustAddFunction(dsl.NewWithMultipleSignatures(
				item.GetName(),
				item.Signatures,
				makeHelperFunctionPluginExecute(ctx.helperFunctions, plugin.Path, item.GetName()),
			))
		} else if item.NumberOfArgs > 0 {
			dsl.MustAddFunction(dsl.NewWithPositionalArgs(
				item.GetName(),
				int(item.NumberOfArgs),
				makeHelperFunctionPluginExecute(ctx.helperFunctions, plugin.Path, item.GetName()),
			))
		}
	}
	gologger.Verbose().Msgf("Loaded helper function plugin %s", plugin.Name)
	return nil
}

// makeHelperFunctionPluginExecute creates a helper function plugin execute function
func makeHelperFunctionPluginExecute(p *proto.HelperFunctionPlugin, path, function string) func(arguments ...interface{}) (interface{}, error) {
	return func(arguments ...interface{}) (interface{}, error) {
		newPlugin, err := p.Load(context.Background(), path)
		if err != nil {
			return nil, errors.Wrap(err, "could not load plugin")
		}
		defer newPlugin.Close(context.Background())

		resp, err := newPlugin.Execute(context.Background(), &proto.HelperFunctionRequest{
			Args: proto.ToAnyScalarArray(arguments),
			Name: function,
		})
		if err != nil {
			return nil, errors.Wrap(err, "could not execute plugin")
		}
		return proto.ToAnyScalarValue(resp.Result), nil
	}
}
